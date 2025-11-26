#pragma once
#include <cstdint>

namespace utils
{
    bool DevicePathToDosPath( const char *devicePath, char *dosPath, size_t dosPathSize );
    void swap( const char** a, const char** b );
    void shuffle( const char** arr, size_t n );
}