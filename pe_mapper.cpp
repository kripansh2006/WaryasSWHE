#include "pe_mapper.hpp"
#include <fstream>

PEMemoryMapper::PEMemoryMapper(const std::string& path)
{
	/* Open file */
	this->binary_.open(path, std::ios::binary);
	/* Parse optional header */
	IMAGE_DOS_HEADER dos_header;
	binary_.seekg(0);
	binary_.read(reinterpret_cast<char*>(&dos_header), sizeof(dos_header));
	IMAGE_NT_HEADERS nt_headers;
	binary_.seekg(dos_header.e_lfanew);
	binary_.read(reinterpret_cast<char*>(&nt_headers), sizeof(nt_headers));
	/* Set base address */
	base_address_ = nt_headers.OptionalHeader.ImageBase;
	/* Set memory size */
	memory_size_ = nt_headers.OptionalHeader.SizeOfImage;

	this->memory_.resize(memory_size_, 0);
	binary_.seekg(0);

	this->map_sections();
}

std::vector<uint8_t> PEMemoryMapper::read_from_va(uint64_t va, size_t size) const
{
	uint64_t offset = va - this->base_address_;
	if (offset + size > this->memory_size_)
	{
		return { };
	}
	return std::vector<uint8_t>(this->memory_.begin() + offset, this->memory_.begin() + offset + size);
}

void PEMemoryMapper::write_to_va(uint64_t va, const std::vector<uint8_t>& data)
{
	uint64_t offset = va - this->base_address_;
	if (offset + data.size() > this->memory_size_)
	{
		return;
	}
	std::copy(data.begin(), data.end(), this->memory_.begin() + offset);
}

bool PEMemoryMapper::is_va_mapped(uint64_t va) const
{
	uint64_t offset = va - this->base_address_;
	if (offset >= this->memory_.size())
	{
		return false;
	}
	return true;
}

uint8_t* PEMemoryMapper::get_data_pointer(uint64_t va)
{
	uint64_t offset = va - this->base_address_;
	if (offset >= this->memory_.size())
	{
		return nullptr;
	}
	return this->memory_.data() + offset;
}

std::vector<uint8_t>& PEMemoryMapper::get_memory()
{
	return this->memory_;
}

uintptr_t PEMemoryMapper::sigscan(const char* pattern)
{
	auto base = this->memory_.data();
	std::string signature = this->hex_to_bytes(pattern);
	u_char first = static_cast<u_char>(signature.at(0));
	u_char* end = (base + memory_size_) - signature.length();
	for (; base < end; ++base)
	{
		if (*base != first)
			continue;
		u_char* bytes = base;
		auto sig = (u_char*)signature.c_str();
		for (; *sig; ++sig, ++bytes)
		{
			if (*sig == '?')
				continue;
			if (*bytes != *sig)
				goto end;
		}
		return (uintptr_t)base;
	end:;
	}
	return NULL;
}

std::string PEMemoryMapper::hex_to_bytes(std::string hex)
{
	std::string bytes;
	std::erase_if(hex, isspace);
	for (uint32_t i = 0; i < hex.length(); i += 2)
	{
		if (static_cast<u_char>(hex[i]) == '?')
		{
			bytes += '?';
			i -= 1;
			continue;
		}
		u_char byte = static_cast<u_char>(std::strtol(hex.substr(i, 2).c_str(), nullptr, 16));
		bytes += byte;
	}
	return bytes;
}

void PEMemoryMapper::map_sections()
{
	// Read DOS Header
	IMAGE_DOS_HEADER dos_header = { };
	if (!read_struct(dos_header, 0))
	{
		return;
	}

	if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
	{
		return;
	}

	// Read NT Headers
	DWORD pe_offset = dos_header.e_lfanew;
	DWORD signature = 0;
	if (!read_struct(signature, pe_offset))
	{
		return;
	}

	if (signature != IMAGE_NT_SIGNATURE)
	{
		return;
	}

	// Read File Header
	IMAGE_FILE_HEADER file_header = { };
	if (!read_struct(file_header, pe_offset + sizeof(DWORD)))
	{
		return;
	}

	// Read and verify Optional Header
	size_t optional_header_offset = pe_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	WORD magic = 0;
	if (!read_struct(magic, optional_header_offset))
	{
		return;
	}

	// Handle PE32 vs PE32+
	if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		IMAGE_OPTIONAL_HEADER32 optional_header = { };
		if (!read_struct(optional_header, optional_header_offset))
		{
			return;
		}
		base_address_ = optional_header.ImageBase;
		memory_size_ = optional_header.SizeOfImage;
	}
	else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		IMAGE_OPTIONAL_HEADER64 optional_header = { };
		if (!read_struct(optional_header, optional_header_offset))
		{
			return;
		}
		base_address_ = optional_header.ImageBase;
		memory_size_ = optional_header.SizeOfImage;
	}
	else
	{
		return;
	}

	// Allocate memory with proper size checks
	if (memory_size_ == 0 || memory_size_ > MAX_REASONABLE_SIZE)
	{
		return;
	}
	memory_.resize(memory_size_, 0);

	// Calculate section headers offset
	size_t section_headers_offset = pe_offset +
		sizeof(DWORD) +
		sizeof(IMAGE_FILE_HEADER) +
		file_header.SizeOfOptionalHeader;

	// Map each section
	for (int i = 0; i < file_header.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER section_header = { };
		if (!read_struct(section_header, section_headers_offset + (i * sizeof(IMAGE_SECTION_HEADER))))
		{
			return;
		}

		// Validate section header
		if (section_header.VirtualAddress >= memory_size_ ||
			section_header.Misc.VirtualSize > memory_size_ ||
			section_header.VirtualAddress + section_header.Misc.VirtualSize > memory_size_)
		{
			return;
		}

		// Calculate correct sizes
		size_t virtual_size = section_header.Misc.VirtualSize;
		if (virtual_size == 0)
		{
			virtual_size = section_header.SizeOfRawData;
		}

		size_t copy_size = min(static_cast<size_t>(section_header.SizeOfRawData), virtual_size);

		// Validate raw data
		if (section_header.PointerToRawData + copy_size > get_file_size())
		{
			return;
		}

		// Copy section data
		binary_.seekg(section_header.PointerToRawData);
		binary_.read(reinterpret_cast<char*>(memory_.data() + section_header.VirtualAddress),
		             copy_size);
	}
}
