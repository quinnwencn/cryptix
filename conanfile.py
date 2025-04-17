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
        "gtest/*:shared": True,
        "fmt/*:shared": True,
    }

    def requirements(self):
        self.requires("openssl/3.0.8")
        self.requires("gtest/1.13.0")
        self.requires("fmt/10.1.0")

    def build_requirements(self):
        self.build_requires("cmake/3.26.4")

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

    # not supported yet
    def test(self):
        if not self.in_local_cache:
            return
        cmake = CMake(self)
        cmake.test()
        cmake.build()
        cmake.test()