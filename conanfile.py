from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps, cmake_layout

class Cryptix(ConanFile):
    name = "cryptix"
    version = "0.1.0"
    description = "Cryptix is a C++ cryptography library."
    settings = "os", "compiler", "build_type", "arch"
    generator = "CMakeDeps"
    exports_sources = "CMakeLists.txt", "include/*", "src/*"

    default_options = {
        "openssl/*:shared": True,
        "gtest/*:shared": True,
        "fmt/*:shared": True,
        "cpputils/*:shared": True,
    }

    def requirements(self):
        self.requires("openssl/3.0.8")
        self.requires("gtest/1.13.0")
        self.requires("fmt/10.1.0")
        self.requires("cpputils/0.5.0")

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

    def package(self):
        cmake = CMake(self)
        cmake.install()


    def package_info(self):
        self.cpp_info.libs = ["cryptix"]
        self.cpp_info.includedirs = ["include"]
        self.cpp_info.set_property("cmake_target_name", "cryptix::cryptix")