// Copyright(c) 2018-2021, Intel Corporation
//
// Redistribution  and  use  in source  and  binary  forms,  with  or  without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of  source code  must retain the  above copyright notice,
//   this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
// * Neither the name  of Intel Corporation  nor the names of its contributors
//   may be used to  endorse or promote  products derived  from this  software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,  BUT NOT LIMITED TO,  THE
// IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT  SHALL THE COPYRIGHT OWNER  OR CONTRIBUTORS BE
// LIABLE  FOR  ANY  DIRECT,  INDIRECT,  INCIDENTAL,  SPECIAL,  EXEMPLARY,  OR
// CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT LIMITED  TO,  PROCUREMENT  OF
// SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE,  DATA, OR PROFITS;  OR BUSINESS
// INTERRUPTION)  HOWEVER CAUSED  AND ON ANY THEORY  OF LIABILITY,  WHETHER IN
// CONTRACT,  STRICT LIABILITY,  OR TORT  (INCLUDING NEGLIGENCE  OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,  EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif // _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <opae/enum.h>

#include "props.h"

struct _fpga_properties *opae_properties_create(void)
{
	struct _fpga_properties *props;
	pthread_mutexattr_t mattr;
	int err;

	props = (struct _fpga_properties *)calloc(
		1, sizeof(struct _fpga_properties));

	if (!props)
		return NULL;

	props->magic = FPGA_PROPERTY_MAGIC;

	if (pthread_mutexattr_init(&mattr)) {
		OPAE_ERR("pthread_mutexattr_init() failed");
		goto out_free;
	}

	if (pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE)) {
		OPAE_ERR("pthread_mutexattr_settype() failed");
		goto out_destroy_attr;
	}

	if (pthread_mutex_init(&props->lock, &mattr)) {
		OPAE_ERR("pthread_mutex_init() failed");
		goto out_destroy_attr;
	}

	pthread_mutexattr_destroy(&mattr);

	return props;

out_destroy_attr:
	err = pthread_mutexattr_destroy(&mattr);
	if (err)
		OPAE_ERR("pthread_mutexattr_destroy() failed: %s",
			 strerror(err));
out_free:
	free(props);
	return NULL;
}

fpga_result __OPAE_API__ fpgaDestroyProperties(fpga_properties *prop)
{
	struct _fpga_properties *p;
	int err;

	ASSERT_NOT_NULL(prop);

	p = opae_validate_and_lock_properties(*prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_PARENT)) {
		// If the parent token has a wrapper that we
		// allocated, then free it.
		opae_wrapped_token *wrapped_token =
			opae_validate_wrapped_token(p->parent);
		if (wrapped_token)
			opae_destroy_wrapped_token(wrapped_token);
	}

	p->magic = 0;

	opae_mutex_unlock(err, &p->lock);

	err = pthread_mutex_destroy(&p->lock);
	if (err)
		OPAE_ERR("pthread_mutex_destroy() failed: %s", strerror(err));

	free(p);
	*prop = NULL;

	return FPGA_OK;
}

fpga_result __OPAE_API__ fpgaCloneProperties(fpga_properties src,
					     fpga_properties *dst)
{
	int err;
	struct _fpga_properties *clone;
	pthread_mutex_t save_lock;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(dst);

	p = opae_validate_and_lock_properties(src);

	ASSERT_NOT_NULL(p);

	clone = opae_properties_create();
	if (!clone) {
		opae_mutex_unlock(err, &p->lock);
		return FPGA_EXCEPTION;
	}

	save_lock = clone->lock;

	*clone = *p;
	clone->lock = save_lock;

	if (FIELD_VALID(p, FPGA_PROPERTY_PARENT)) {
		opae_wrapped_token *wrapped_token =
			opae_validate_wrapped_token(p->parent);
		if (wrapped_token)
			opae_upref_wrapped_token(wrapped_token);
	}

	*dst = clone;

	opae_mutex_unlock(err, &p->lock);

	return FPGA_OK;
}

fpga_result __OPAE_API__ fpgaClearProperties(fpga_properties props)
{
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(props);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_PARENT)) {
		opae_wrapped_token *wrapped_token =
			opae_validate_wrapped_token(p->parent);
		if (wrapped_token) {
			opae_downref_wrapped_token(wrapped_token);
			p->parent = NULL;
		}
	}
	p->valid_fields = 0;

	opae_mutex_unlock(err, &p->lock);

	return FPGA_OK;
}

fpga_result __OPAE_API__ fpgaPropertiesGetParent(const fpga_properties prop,
						 fpga_token *parent)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(parent);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_PARENT)) {
		*parent = p->parent;
	} else {
		OPAE_DBG("No parent");
		res = FPGA_NOT_FOUND;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetParent(fpga_properties prop,
						 fpga_token parent)
{
	int err;
	struct _fpga_properties *p;
	opae_wrapped_token *wrapped_token;

	ASSERT_NOT_NULL(parent);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_PARENT)) {
		// If we have a wrapped parent token that we
		// allocated, then free it.
		wrapped_token = opae_validate_wrapped_token(p->parent);
		if (wrapped_token)
			opae_destroy_wrapped_token(wrapped_token);
	}

	wrapped_token = opae_validate_wrapped_token(parent);
	if (wrapped_token)
		opae_upref_wrapped_token(wrapped_token);

	p->parent = parent;
	SET_FIELD_VALID(p, FPGA_PROPERTY_PARENT);

	opae_mutex_unlock(err, &p->lock);

	return FPGA_OK;
}

fpga_result __OPAE_API__ fpgaPropertiesGetObjectType(
	const fpga_properties prop, fpga_objtype *objtype)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(objtype);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE)) {
		*objtype = p->objtype;
	} else {
		OPAE_MSG("No object type");
		res = FPGA_NOT_FOUND;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetObjectType(fpga_properties prop,
						     fpga_objtype objtype)
{
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	p->objtype = objtype;
	SET_FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE);

	opae_mutex_unlock(err, &p->lock);

	return FPGA_OK;
}

fpga_result __OPAE_API__ fpgaPropertiesGetSegment(const fpga_properties prop,
						  uint16_t *segment)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(segment);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_SEGMENT)) {
		*segment = p->segment;
	} else {
		OPAE_MSG("No segment");
		res = FPGA_NOT_FOUND;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetSegment(fpga_properties prop,
						  uint16_t segment)
{
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	SET_FIELD_VALID(p, FPGA_PROPERTY_SEGMENT);
	p->segment = segment;

	opae_mutex_unlock(err, &p->lock);

	return FPGA_OK;
}

fpga_result __OPAE_API__ fpgaPropertiesGetBus(const fpga_properties prop,
					      uint8_t *bus)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(bus);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_BUS)) {
		*bus = p->bus;
	} else {
		OPAE_MSG("No bus");
		res = FPGA_NOT_FOUND;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetBus(fpga_properties prop,
					      uint8_t bus)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	SET_FIELD_VALID(p, FPGA_PROPERTY_BUS);
	p->bus = bus;

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetDevice(const fpga_properties prop,
						 uint8_t *device)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(device);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_DEVICE)) {
		*device = p->device;
	} else {
		OPAE_MSG("No device");
		res = FPGA_NOT_FOUND;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetDevice(fpga_properties prop,
						 uint8_t device)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	SET_FIELD_VALID(p, FPGA_PROPERTY_DEVICE);
	p->device = device;

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetFunction(const fpga_properties prop,
						   uint8_t *function)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(function);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_FUNCTION)) {
		*function = p->function;
	} else {
		OPAE_MSG("No function");
		res = FPGA_NOT_FOUND;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetFunction(fpga_properties prop,
						   uint8_t function)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	// PCIe supports 8 functions per device.
	if (function > 7) {
		OPAE_MSG("Invalid function number");
		return FPGA_INVALID_PARAM;
	}

	p = opae_validate_and_lock_properties(prop);
	ASSERT_NOT_NULL(p);

	SET_FIELD_VALID(p, FPGA_PROPERTY_FUNCTION);
	p->function = function;

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetSocketID(const fpga_properties prop,
						   uint8_t *socket_id)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(socket_id);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_SOCKETID)) {
		*socket_id = p->socket_id;
	} else {
		OPAE_MSG("No socket ID");
		res = FPGA_NOT_FOUND;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetSocketID(fpga_properties prop,
						   uint8_t socket_id)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	SET_FIELD_VALID(p, FPGA_PROPERTY_SOCKETID);
	p->socket_id = socket_id;

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetDeviceID(const fpga_properties prop,
						   uint16_t *device_id)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(device_id);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_DEVICEID)) {
		*device_id = p->device_id;
	} else {
		OPAE_MSG("No device ID");
		res = FPGA_NOT_FOUND;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetDeviceID(fpga_properties prop,
						   uint16_t device_id)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	SET_FIELD_VALID(p, FPGA_PROPERTY_DEVICEID);
	p->device_id = device_id;

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetNumSlots(const fpga_properties prop,
						   uint32_t *num_slots)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(num_slots);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE)
	    && FPGA_DEVICE == p->objtype) {
		if (FIELD_VALID(p, FPGA_PROPERTY_NUM_SLOTS)) {
			*num_slots = p->u.fpga.num_slots;
		} else {
			OPAE_MSG("No number of slots");
			res = FPGA_NOT_FOUND;
		}
	} else {
		OPAE_ERR(
			"Attempting to get num_slots from invalid object type: %d",
			p->objtype);
		res = FPGA_INVALID_PARAM;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetNumSlots(fpga_properties prop,
						   uint32_t num_slots)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE)
	    && FPGA_DEVICE == p->objtype) {
		SET_FIELD_VALID(p, FPGA_PROPERTY_NUM_SLOTS);
		p->u.fpga.num_slots = num_slots;
	} else {
		OPAE_ERR(
			"Attempting to set num slots on invalid object type: %d",
			p->objtype);
		res = FPGA_INVALID_PARAM;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetBBSID(const fpga_properties prop,
						uint64_t *bbs_id)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(bbs_id);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE)
	    && FPGA_DEVICE == p->objtype) {
		if (FIELD_VALID(p, FPGA_PROPERTY_BBSID)) {
			*bbs_id = p->u.fpga.bbs_id;
		} else {
			OPAE_MSG("No BBS ID");
			res = FPGA_NOT_FOUND;
		}
	} else {
		OPAE_ERR(
			"Attempting to get BBS ID from invalid object type: %d",
			p->objtype);
		res = FPGA_INVALID_PARAM;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetBBSID(fpga_properties prop,
						uint64_t bbs_id)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE)
	    && FPGA_DEVICE == p->objtype) {
		SET_FIELD_VALID(p, FPGA_PROPERTY_BBSID);
		p->u.fpga.bbs_id = bbs_id;
	} else {
		OPAE_ERR("Attempting to set BBS ID on invalid object type: %d",
			 p->objtype);
		res = FPGA_INVALID_PARAM;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetBBSVersion(const fpga_properties prop,
						     fpga_version *bbs_version)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(bbs_version);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE)
	    && FPGA_DEVICE == p->objtype) {
		if (FIELD_VALID(p, FPGA_PROPERTY_BBSVERSION)) {
			*bbs_version = p->u.fpga.bbs_version;
		} else {
			OPAE_MSG("No BBS version");
			res = FPGA_NOT_FOUND;
		}
	} else {
		OPAE_ERR(
			"Attempting to get BBS version from invalid object type: %d",
			p->objtype);
		res = FPGA_INVALID_PARAM;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetBBSVersion(fpga_properties prop,
						     fpga_version bbs_version)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE)
	    && FPGA_DEVICE == p->objtype) {
		SET_FIELD_VALID(p, FPGA_PROPERTY_BBSVERSION);
		p->u.fpga.bbs_version = bbs_version;
	} else {
		OPAE_ERR(
			"Attempting to set BBS version on invalid object type: %d",
			p->objtype);
		res = FPGA_INVALID_PARAM;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetVendorID(const fpga_properties prop,
						   uint16_t *vendor_id)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(vendor_id);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_VENDORID)) {
		*vendor_id = p->vendor_id;
	} else {
		OPAE_MSG("No vendor ID");
		res = FPGA_NOT_FOUND;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetVendorID(fpga_properties prop,
						   uint16_t vendor_id)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	SET_FIELD_VALID(p, FPGA_PROPERTY_VENDORID);
	p->vendor_id = vendor_id;

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetModel(const fpga_properties prop,
						char *model)
{
	UNUSED_PARAM(prop);
	UNUSED_PARAM(model);
	OPAE_MSG("Model not supported");
	return FPGA_NOT_SUPPORTED;
}

fpga_result __OPAE_API__ fpgaPropertiesSetModel(fpga_properties prop,
						char *model)
{
	UNUSED_PARAM(prop);
	UNUSED_PARAM(model);
	OPAE_MSG("Model not supported");
	return FPGA_NOT_SUPPORTED;
}

fpga_result __OPAE_API__ fpgaPropertiesGetLocalMemorySize(
	const fpga_properties prop, uint64_t *local_memory_size)
{
	UNUSED_PARAM(prop);
	UNUSED_PARAM(local_memory_size);
	OPAE_MSG("Local memory not supported");
	return FPGA_NOT_SUPPORTED;
}

fpga_result __OPAE_API__ fpgaPropertiesSetLocalMemorySize(fpga_properties prop,
						uint64_t local_memory_size)
{
	UNUSED_PARAM(prop);
	UNUSED_PARAM(local_memory_size);
	OPAE_MSG("Local memory not supported");
	return FPGA_NOT_SUPPORTED;
}

fpga_result __OPAE_API__ fpgaPropertiesGetCapabilities(
	const fpga_properties prop, uint64_t *capabilities)
{
	UNUSED_PARAM(prop);
	UNUSED_PARAM(capabilities);
	OPAE_MSG("Capabilities not supported");
	return FPGA_NOT_SUPPORTED;
}

fpga_result __OPAE_API__ fpgaPropertiesSetCapabilities(fpga_properties prop,
						       uint64_t capabilities)
{
	UNUSED_PARAM(prop);
	UNUSED_PARAM(capabilities);
	OPAE_MSG("Capabilities not supported");
	return FPGA_NOT_SUPPORTED;
}

fpga_result __OPAE_API__ fpgaPropertiesGetGUID(const fpga_properties prop,
					       fpga_guid *guid)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(guid);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_GUID)) {
		memcpy(*guid, p->guid, sizeof(fpga_guid));
	} else {
		OPAE_MSG("No GUID");
		res = FPGA_NOT_FOUND;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetGUID(fpga_properties prop,
					       fpga_guid guid)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	SET_FIELD_VALID(p, FPGA_PROPERTY_GUID);

	memcpy(p->guid, guid, sizeof(fpga_guid));

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetNumMMIO(const fpga_properties prop,
						  uint32_t *mmio_spaces)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(mmio_spaces);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE)
	    && FPGA_ACCELERATOR == p->objtype) {
		if (FIELD_VALID(p, FPGA_PROPERTY_NUM_MMIO)) {
			*mmio_spaces = p->u.accelerator.num_mmio;
		} else {
			OPAE_MSG("No MMIO spaces");
			res = FPGA_NOT_FOUND;
		}
	} else {
		OPAE_ERR(
			"Attempting to get number of MMIO spaces from invalid object type: %d",
			p->objtype);
		res = FPGA_INVALID_PARAM;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetNumMMIO(fpga_properties prop,
						  uint32_t mmio_spaces)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE)
	    && FPGA_ACCELERATOR == p->objtype) {
		SET_FIELD_VALID(p, FPGA_PROPERTY_NUM_MMIO);
		p->u.accelerator.num_mmio = mmio_spaces;
	} else {
		OPAE_ERR(
			"Attempting to set number of MMIO spaces on invalid object type: %d",
			p->objtype);
		res = FPGA_INVALID_PARAM;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetNumInterrupts(
	const fpga_properties prop, uint32_t *num_interrupts)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(num_interrupts);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE)
	    && FPGA_ACCELERATOR == p->objtype) {
		if (FIELD_VALID(p, FPGA_PROPERTY_NUM_INTERRUPTS)) {
			*num_interrupts = p->u.accelerator.num_interrupts;
		} else {
			OPAE_MSG("No interrupts");
			res = FPGA_NOT_FOUND;
		}
	} else {
		OPAE_ERR(
			"Attempting to get number of interrupts from invalid object type: %d",
			p->objtype);
		res = FPGA_INVALID_PARAM;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetNumInterrupts(fpga_properties prop,
							uint32_t num_interrupts)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE)
	    && FPGA_ACCELERATOR == p->objtype) {
		SET_FIELD_VALID(p, FPGA_PROPERTY_NUM_INTERRUPTS);
		p->u.accelerator.num_interrupts = num_interrupts;
	} else {
		OPAE_ERR(
			"Attempting to set number of interrupts on invalid object type: %d",
			p->objtype);
		res = FPGA_INVALID_PARAM;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetAcceleratorState(
	const fpga_properties prop, fpga_accelerator_state *state)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(state);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE)
	    && FPGA_ACCELERATOR == p->objtype) {
		if (FIELD_VALID(p, FPGA_PROPERTY_ACCELERATOR_STATE)) {
			*state = p->u.accelerator.state;
		} else {
			OPAE_MSG("No accelerator state");
			res = FPGA_NOT_FOUND;
		}
	} else {
		OPAE_ERR("Attempting to get state from invalid object type: %d",
			 p->objtype);
		res = FPGA_INVALID_PARAM;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetAcceleratorState(
	fpga_properties prop, fpga_accelerator_state state)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJTYPE)
	    && FPGA_ACCELERATOR == p->objtype) {
		SET_FIELD_VALID(p, FPGA_PROPERTY_ACCELERATOR_STATE);
		p->u.accelerator.state = state;
	} else {
		OPAE_ERR("Attempting to set state from invalid object type: %d",
			 p->objtype);
		res = FPGA_INVALID_PARAM;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetObjectID(const fpga_properties prop,
						   uint64_t *object_id)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(object_id);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_OBJECTID)) {
		*object_id = p->object_id;
	} else {
		OPAE_MSG("No object ID");
		res = FPGA_NOT_FOUND;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetObjectID(fpga_properties prop,
						   uint64_t object_id)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	SET_FIELD_VALID(p, FPGA_PROPERTY_OBJECTID);
	p->object_id = object_id;

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetNumErrors(const fpga_properties prop,
						    uint32_t *num_errors)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(num_errors);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_NUM_ERRORS)) {
		*num_errors = p->num_errors;
	} else {
		OPAE_MSG("No num errors");
		res = FPGA_NOT_FOUND;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetNumErrors(const fpga_properties prop,
						    uint32_t num_errors)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	SET_FIELD_VALID(p, FPGA_PROPERTY_NUM_ERRORS);
	p->num_errors = num_errors;

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesGetInterface(const fpga_properties prop,
						    fpga_interface *interface)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p;

	ASSERT_NOT_NULL(interface);

	p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	if (FIELD_VALID(p, FPGA_PROPERTY_INTERFACE)) {
		*interface = p->interface;
	} else {
		OPAE_DBG("No plugin interface");
		res = FPGA_NOT_FOUND;
	}

	opae_mutex_unlock(err, &p->lock);

	return res;
}

fpga_result __OPAE_API__ fpgaPropertiesSetInterface(const fpga_properties prop,
						    fpga_interface interface)
{
	fpga_result res = FPGA_OK;
	int err;
	struct _fpga_properties *p = opae_validate_and_lock_properties(prop);

	ASSERT_NOT_NULL(p);

	SET_FIELD_VALID(p, FPGA_PROPERTY_INTERFACE);
	p->interface = interface;

	opae_mutex_unlock(err, &p->lock);

	return res;
}
