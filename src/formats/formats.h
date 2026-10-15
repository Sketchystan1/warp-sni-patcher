#pragma once

#include "../patcher.h"

namespace warp {

// Format detectors
inline bool is_elf(const Bytes& data) {
    return data.size() >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
}
inline bool is_macho(const Bytes& data) {
    if (data.size() < 4) return false;
    const std::uint32_t magic = (std::uint32_t(data[0]) << 24) |
        (std::uint32_t(data[1]) << 16) | (std::uint32_t(data[2]) << 8) | data[3];
    return magic == 0xcffaedfe || magic == 0xfeedfacf || magic == 0xcafebabe ||
           magic == 0xbebafeca || magic == 0xcafebabf || magic == 0xbfbafeca;
}
inline bool is_pe(const Bytes& data) {
    return data.size() >= 2 && data[0] == 'M' && data[1] == 'Z';
}

// Format parsers & patchers
Inspection inspect_elf(const Bytes& data);
PatchResult patch_elf(const Bytes& data, const PatchOptions& options);

Inspection inspect_macho(const Bytes& data);
PatchResult patch_macho(const Bytes& data, const PatchOptions& options);

Inspection inspect_pe(const Bytes& data);
PatchResult patch_pe(const Bytes& data, const PatchOptions& options);

} // namespace warp
