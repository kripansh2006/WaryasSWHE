#include <Windows.h>
#include <vector>
#include <string>
#include <fstream>

class PEMemoryMapper
{
public:
    PEMemoryMapper( const std::string& path );

    
    std::vector<uint8_t> read_from_va( uint64_t va, size_t size ) const;
    void write_to_va( uint64_t va, const std::vector<uint8_t> &data );
    bool is_va_mapped( uint64_t va ) const;
    uint8_t* get_data_pointer( uint64_t va );
    std::vector<uint8_t>& get_memory( );
    uintptr_t sigscan( const char* pattern );

    template<typename T>
    bool read_struct(T& structure, size_t offset) {
        binary_.seekg(offset);
        binary_.read(reinterpret_cast<char*>(&structure), sizeof(T));
        return binary_.good();
    }

    size_t get_file_size() {
        auto current_pos = binary_.tellg();
        binary_.seekg(0, std::ios::end);
        size_t size = binary_.tellg();
        binary_.seekg(current_pos);
        return size;
    }

    template<typename T>
    T read( uint64_t va ) const
    {
        return *reinterpret_cast<T *>( this->read_from_va( va, sizeof( T ) ).data( ) );
    }
private:
    static constexpr size_t MAX_REASONABLE_SIZE = 1ULL << 31;

    std::ifstream binary_;
    uint64_t base_address_;
    uint64_t memory_size_;
    std::vector<uint8_t> memory_;
    std::string hex_to_bytes( std::string hex );
    void map_sections( );
};