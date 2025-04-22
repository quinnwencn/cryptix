from conan import ConanFile
from conan.tools.cmake import CMake, cmake_layout


class TestPackage(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps", "CMakeToolchain"

    def requirements(self):
        self.requires("cryptix/0.1.0")
        self.requires("gtest/1.13.0", visible=False)
        
    def layout(self):
        cmake_layout(self)

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def test(self):
        cmake = CMake(self)
        cmake.test()
