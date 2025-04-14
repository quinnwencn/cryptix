from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps, cmake_layout

class Cryptix(ConanFile):
    name = "Cryptix"
    version = "0.1.0"
    description = "Cryptix is a C++ cryptography library."
    settings = "os", "compiler", "build_type", "arch"
    generator = "CMakeDeps"

    default_options = {
        "openssl/*:shared": True,
        "gtest/*:shared": True
    }

    def requirements(self):
        self.requires("openssl/3.0.8")
        self.requires("gtest/1.13.0")

    def build_requirements(self):
        self.build_requires("cmake/3.20.0")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        tc = CMakeToolchain(self)
        tc.generate()

        deps = CMakeDeps(self)
        deps.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()