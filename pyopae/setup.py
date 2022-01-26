import os
from setuptools import setup, find_packages
from setuptools.command.build_ext import build_ext
from distutils.extension import Extension




# get the original build_extensions method
original_build_extensions = build_ext.build_extensions


def override_build_extensions(self):
    if '-Wstrict-prototypes' in self.compiler.compiler_so:
        self.compiler.compiler_so.remove('-Wstrict-prototypes')
    self.compiler.compiler_so.append('-fvisibility=hidden')
    # call the original build_extensions
    original_build_extensions(self)


# replace build_extensions with our custom version
build_ext.build_extensions = override_build_extensions


class pybind_include_dirs(object):
    def __init__(self, user=False):
        self.user = user

    def __str__(self):
        import pybind11
        return pybind11.get_include(self.user)


extensions = [
    Extension("opae_ase.fpga._opae_ase",
              sources=["pyproperties.cpp",
                       "pycontext.cpp",
                       "pyhandle.cpp",
                       "pytoken.cpp",
                       "pyshared_buffer.cpp",
                       "pyevents.cpp",
                       "pyerrors.cpp",
                       "opae.cpp"],
              language="c++",
              extra_compile_args=["-std=c++11"],
              extra_link_args=["-std=c++11"],
              include_dirs=[
                  pybind_include_dirs(),
                  pybind_include_dirs(True)
              ],
              libraries=["opae-c-ase", "opae-cxx-core"])
]

setup(
    name="opae_ase.fpga",
    version="1.1.2",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
        ]
    },
    ext_modules=extensions,
    install_requires=['pybind11>=2.2'],
    description="pyopae provides Python bindings around the "
                "OPAE C API",
    license="BSD3",
    keywords="OPAE accelerator fpga bindings",
    url="https://01.org/OPAE",
)
