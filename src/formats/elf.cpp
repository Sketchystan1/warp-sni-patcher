#include "formats.h"
#include "../patcher.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>




namespace warp {
namespace elf_impl {
using namespace warp;

namespace {

// These recognizers intentionally describe the complete compiler sequences
// inspected in Cloudflare's Ubuntu amd64 2026.8.2100.0 and 2026.8.2110.0 packages.
// Unsupported instruction layouts fail closed instead of guessing at nearby
// integers. No offsets or virtual addresses from that build are hard-coded.
[[noreturn]] void fail(const std::string& message) {
    throw std::runtime_error("ELF: " + message);
}

void require_range(const Bytes& data, std::uint64_t offset, std::uint64_t size) {
    if (offset > data.size() || size > data.size() - offset)
        fail("truncated or invalid file range");
}

std::uint64_t integer(const Bytes& data, std::uint64_t offset, unsigned size) {
    require_range(data, offset, size);
    std::uint64_t result = 0;
    for (unsigned i = 0; i < size; ++i)
        result |= std::uint64_t(data[static_cast<std::size_t>(offset + i)]) << (8 * i);
    return result;
}

void put(Bytes& data, std::uint64_t offset, std::uint64_t value, unsigned size) {
    require_range(data, offset, size);
    for (unsigned i = 0; i < size; ++i)
        data[static_cast<std::size_t>(offset + i)] = static_cast<std::uint8_t>(value >> (8 * i));
}

struct Section {
    std::string name;
    std::uint32_t type;
    std::uint64_t flags, address, offset, size, entry_size;
    std::uint32_t link;

    bool code() const { return type == 1 && (flags & 6) == 6; }
    bool data() const { return type == 1 && (flags & 2) && !(flags & 4); }
};

struct Function {
    std::uint64_t address, size;
    std::string name;
};

struct Relocation {
    std::uint64_t address, target, entry_offset;
};

struct Lea {
    std::uint64_t offset, address, target;
};

struct LoadSegment {
    std::uint64_t address, offset, file_size, memory_size, flags;
};

struct Elf {
    const Bytes& bytes;
    std::vector<Section> sections;
    std::vector<Function> functions;
    std::map<std::uint64_t, Relocation> relocations;
    std::vector<std::uint64_t> unsupported_addends;
    std::vector<Lea> leas;
    std::uint16_t machine;

    explicit Elf(const Bytes& input) : bytes(input), machine(0) {
        require_range(bytes, 0, 64);
        if (integer(bytes, 0, 4) != 0x464c457f || bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1)
            fail("expected a little-endian 64-bit ELF file");
        const auto type = integer(bytes, 16, 2);
        if ((type != 2 && type != 3) || integer(bytes, 20, 4) != 1 || integer(bytes, 52, 2) != 64)
            fail("unsupported ELF header");
        machine = static_cast<std::uint16_t>(integer(bytes, 18, 2));
        const auto program_table = integer(bytes, 32, 8);
        const auto program_entry = integer(bytes, 54, 2);
        const auto program_count = integer(bytes, 56, 2);
        if (program_entry != 56 || !program_count || program_count == 0xffff)
            fail("missing or unsupported program-header table");
        require_range(bytes, program_table, program_entry * program_count);
        std::vector<LoadSegment> loads;
        for (std::uint64_t i = 0; i < program_count; ++i) {
            const auto p = program_table + program_entry * i;
            if (integer(bytes, p, 4) != 1) continue;
            LoadSegment load{integer(bytes, p + 16, 8), integer(bytes, p + 8, 8),
                             integer(bytes, p + 32, 8), integer(bytes, p + 40, 8), integer(bytes, p + 4, 4)};
            const auto alignment = integer(bytes, p + 48, 8);
            require_range(bytes, load.offset, load.file_size);
            if (load.file_size > load.memory_size || load.address > std::numeric_limits<std::uint64_t>::max() - load.memory_size ||
                (alignment > 1 && ((alignment & (alignment - 1)) || load.address % alignment != load.offset % alignment)))
                fail("invalid load segment");
            loads.push_back(load);
        }
        if (loads.empty()) fail("ELF has no loadable segments");
        const auto table = integer(bytes, 40, 8);
        const auto entry = integer(bytes, 58, 2);
        const auto count = integer(bytes, 60, 2);
        const auto names_index = integer(bytes, 62, 2);
        if (entry != 64 || count == 0 || names_index >= count)
            fail("missing or unsupported section table");
        require_range(bytes, table, entry * count);
        const auto names_header = table + names_index * entry;
        const auto names_offset = integer(bytes, names_header + 24, 8);
        const auto names_size = integer(bytes, names_header + 32, 8);
        require_range(bytes, names_offset, names_size);
        for (std::uint64_t i = 0; i < count; ++i) {
            const auto h = table + entry * i;
            Section section{read_string(names_offset, names_size, integer(bytes, h, 4)),
                static_cast<std::uint32_t>(integer(bytes, h + 4, 4)), integer(bytes, h + 8, 8),
                integer(bytes, h + 16, 8), integer(bytes, h + 24, 8), integer(bytes, h + 32, 8),
                integer(bytes, h + 56, 8), static_cast<std::uint32_t>(integer(bytes, h + 40, 4))};
            if (section.type != 8) require_range(bytes, section.offset, section.size);
            if (section.address > std::numeric_limits<std::uint64_t>::max() - section.size)
                fail("overflowing section address");
            if (section.flags & 2) {
                // Leave room for signed RIP displacements during instruction decoding.
                const auto maximum = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) - 0x80000008ULL;
                if (section.address > maximum || section.size > maximum - section.address)
                    fail("unsupported high virtual address");
                if (section.type != 8 && section.size) {
                    unsigned matches = 0;
                    for (const auto& load : loads) {
                        if (section.address < load.address) continue;
                        const auto delta = section.address - load.address;
                        if (delta <= load.file_size && section.size <= load.file_size - delta &&
                            section.offset == load.offset + delta && (!section.code() || (load.flags & 1))) ++matches;
                    }
                    if (matches != 1) fail("section address/file mapping disagrees with load segments");
                }
            }
            sections.push_back(std::move(section));
        }
    }

    std::string read_string(std::uint64_t offset, std::uint64_t size, std::uint64_t index) const {
        if (index >= size) fail("invalid string-table index");
        const auto begin = offset + index;
        auto end = begin;
        while (end < offset + size && bytes[static_cast<std::size_t>(end)]) ++end;
        if (end == offset + size) fail("unterminated string-table entry");
        return std::string(bytes.begin() + static_cast<std::size_t>(begin), bytes.begin() + static_cast<std::size_t>(end));
    }

    const Section& section_at(std::uint64_t address, std::uint64_t size = 1) const {
        const Section* found = nullptr;
        for (const auto& section : sections) {
            if (section.type == 8 || !(section.flags & 2) || address < section.address) continue;
            const auto delta = address - section.address;
            if (delta <= section.size && size <= section.size - delta) {
                if (found) fail("overlapping allocated sections");
                found = &section;
            }
        }
        if (!found) fail("reference outside file-backed allocated sections");
        return *found;
    }

    std::uint64_t file_offset(std::uint64_t address, std::uint64_t size = 1) const {
        const auto& section = section_at(address, size);
        return section.offset + address - section.address;
    }

    bool function_contains(std::uint64_t address, std::uint64_t size, const std::string& name) const {
        for (const auto& function : functions) {
            if (address >= function.address && address - function.address <= function.size &&
                size <= function.size - (address - function.address) && function.name.find(name) != std::string::npos)
                return true;
        }
        return false;
    }

    void analyze() {
        if (machine != 62) fail("patching currently supports Linux x86_64 only");
        for (const auto& section : sections) {
            if (section.type == 2) {
                if (section.entry_size != 24 || section.size % 24 || section.link >= sections.size())
                    fail("invalid symbol table");
                const auto& strings = sections[section.link];
                if (strings.type != 3) fail("invalid symbol string table");
                for (std::uint64_t offset = section.offset; offset < section.offset + section.size; offset += 24) {
                    const auto info = integer(bytes, offset + 4, 1);
                    const auto size = integer(bytes, offset + 16, 8);
                    if ((info & 15) != 2 || !size) continue;
                    const auto index = integer(bytes, offset + 6, 2);
                    if (index == 0 || index >= sections.size() || !sections[index].code()) continue;
                    const auto address = integer(bytes, offset + 8, 8);
                    file_offset(address, size);
                    functions.push_back({address, size, read_string(strings.offset, strings.size, integer(bytes, offset, 4))});
                }
            } else if (section.type == 4) {
                if (section.entry_size != 24 || section.size % 24) fail("invalid RELA relocation table");
                for (std::uint64_t offset = section.offset; offset < section.offset + section.size; offset += 24) {
                    const auto info = integer(bytes, offset + 8, 8);
                    if (info != 8) {
                        unsupported_addends.push_back(integer(bytes, offset + 16, 8));
                        continue; // Only R_X86_64_RELATIVE, with no symbol, is supported.
                    }
                    const auto address = integer(bytes, offset, 8);
                    file_offset(address, 8);
                    if (!relocations.emplace(address, Relocation{address, integer(bytes, offset + 16, 8), offset}).second)
                        fail("duplicate relocation destinations");
                }
            } else if (section.type == 9 || section.type == 19) {
                if (section.size) fail("REL and packed RELR relocations are not supported");
            }
        }
        if (functions.empty()) fail("function symbols are required to verify compiler patterns; stripped binaries are unsupported");
        for (const auto& section : sections) {
            if (!section.code() || section.size < 7) continue;
            for (std::uint64_t offset = section.offset; offset <= section.offset + section.size - 7; ++offset) {
                const auto rex = bytes[static_cast<std::size_t>(offset)];
                if ((rex & 0xf8) != 0x48 || bytes[static_cast<std::size_t>(offset + 1)] != 0x8d ||
                    (bytes[static_cast<std::size_t>(offset + 2)] & 0xc7) != 5) continue;
                const auto address = section.address + offset - section.offset;
                auto displacement = static_cast<std::int64_t>(integer(bytes, offset + 3, 4));
                if (displacement >= 0x80000000LL) displacement -= 0x100000000LL;
                const auto target = static_cast<std::int64_t>(address + 7) + displacement;
                if (target >= 0) leas.push_back({offset, address, static_cast<std::uint64_t>(target)});
            }
        }
    }
};

constexpr std::array<const char*, 4> masque_names = {
    "consumer-masque.cloudflareclient.com", "consumer-masque-proxy.cloudflareclient.com",
    "zt-masque.cloudflareclient.com", "zt-masque-proxy.cloudflareclient.com"};
constexpr std::array<const char*, 3> registration_names = {
    "api.cloudflareclient.com", "api.devices.cloudflare.com", "api.devices.fed.cloudflare.com"};

struct Host {
    std::uint64_t address, offset;
    std::string text;
    std::size_t kind;
};

template<std::size_t N>
std::vector<Host> hosts(const Elf& elf, const std::array<const char*, N>& names) {
    std::vector<Host> result;
    for (const auto& section : elf.sections) {
        if (!section.data()) continue;
        for (std::size_t kind = 0; kind < names.size(); ++kind) {
            const std::string name = names[kind];
            auto begin = elf.bytes.begin() + static_cast<std::size_t>(section.offset);
            const auto end = begin + static_cast<std::size_t>(section.size);
            while (begin != end) {
                const auto match = std::search(begin, end, name.begin(), name.end());
                if (match == end) break;
                const auto offset = static_cast<std::uint64_t>(match - elf.bytes.begin());
                auto text = name;
                if (match + static_cast<std::ptrdiff_t>(name.size()) != end && *(match + static_cast<std::ptrdiff_t>(name.size())) == '.') text += '.';
                result.push_back({section.address + offset - section.offset, offset, text, kind});
                begin = match + static_cast<std::ptrdiff_t>(text.size());
            }
        }
    }
    return result;
}

std::string architecture(std::uint16_t machine) {
    if (machine == 62) return "x86_64";
    if (machine == 183) return "arm64";
    return "ELF machine " + std::to_string(machine);
}

Inspection inspection(const Elf& elf) {
    Inspection result;
    result.format = "ELF64";
    result.architectures = {architecture(elf.machine)};
    result.masque_occurrences = hosts(elf, masque_names).size();
    for (const auto& host : hosts(elf, registration_names))
        if (host.kind == 0) ++result.registration_occurrences;
    result.notes.push_back("Patching supports verified Linux x86_64 compiler patterns; inspection alone does not establish compatibility.");
    return result;
}

template<std::size_t N>
std::array<Host, N> unique_hosts(const std::vector<Host>& found, const std::string& family) {
    std::array<Host, N> result{};
    std::array<unsigned, N> counts{};
    for (const auto& host : found) {
        if (host.kind >= N) fail("invalid hostname family");
        result[host.kind] = host;
        ++counts[host.kind];
    }
    for (const auto count : counts)
        if (count != 1) fail("expected one original " + family + " literal per variant; binary is patched or unsupported");
    return result;
}

bool matches(const Bytes& bytes, std::uint64_t offset, const std::vector<int>& pattern) {
    if (offset > bytes.size() || pattern.size() > bytes.size() - offset) return false;
    for (std::size_t i = 0; i < pattern.size(); ++i)
        if (pattern[i] >= 0 && bytes[static_cast<std::size_t>(offset) + i] != pattern[i]) return false;
    return true;
}

std::vector<Lea> references(const Elf& elf, std::uint64_t address) {
    std::vector<Lea> result;
    for (const auto& lea : elf.leas) if (lea.target == address) result.push_back(lea);
    return result;
}

void overwrite(Bytes& result, const Host& host, const std::string& replacement) {
    if (replacement.size() > host.text.size()) fail("replacement exceeds packed literal capacity");
    std::copy(replacement.begin(), replacement.end(), result.begin() + static_cast<std::size_t>(host.offset));
    // Leave tail-merged suffixes intact; verified Rust slice lengths bound reads.
}

void reject_extra_references(const Elf& elf, const std::vector<Host>& literals, std::size_t overwritten) {
    for (const auto& host : literals) {
        const auto end = host.address + std::min(overwritten, host.text.size());
        for (const auto& lea : elf.leas)
            if (lea.target > host.address && lea.target < end)
                fail("a code reference shares an overwritten hostname prefix");
        for (const auto& item : elf.relocations)
            if (item.second.target > host.address && item.second.target < end)
                fail("a relocated pointer shares an overwritten hostname prefix");
        for (const auto addend : elf.unsupported_addends)
            if (addend >= host.address && addend < end)
                fail("unsupported relocation references a hostname literal");
    }
    // PIE normally stores these pointers in RELA addends. An additional raw
    // pointer would be an unhandled reference, even if the known patterns match.
    for (const auto& section : elf.sections) {
        if (!section.data() || section.size < 8) continue;
        auto value = integer(elf.bytes, section.offset, 8);
        for (std::uint64_t delta = 0; delta <= section.size - 8; ++delta) {
            for (const auto& host : literals) {
                if (value >= host.address && value < host.address + std::min(overwritten, host.text.size())) {
                    const auto relocation = elf.relocations.find(section.address + delta);
                    if (relocation == elf.relocations.end() || relocation->second.target != value)
                        fail("untracked absolute pointer into a hostname literal");
                }
            }
            if (delta < section.size - 8)
                value = (value >> 8) | (std::uint64_t(elf.bytes[static_cast<std::size_t>(section.offset + delta + 8)]) << 56);
        }
    }
}

void patch_masque(const Elf& elf, Bytes& result, const std::string& replacement) {
    const auto found = unique_hosts<4>(hosts(elf, masque_names), "MASQUE");
    if (replacement.empty() || replacement.size() > 30) fail("MASQUE hostname must contain 1 to 30 ASCII bytes");
    for (std::size_t i = 0; i < found.size(); ++i)
        if (found[i].text != masque_names[i]) fail("dotted MASQUE compiler patterns have not been verified");
    const auto proxy_refs = references(elf, found[1].address);
    if (proxy_refs.size() != 1) fail("unsupported MASQUE references");
    const auto start = proxy_refs.front();
    const std::vector<int> pattern = {
        0x48,0x8d,0x05,-1,-1,-1,-1, 0x48,0x8d,0x0d,-1,-1,-1,-1,
        0x84,0xdb, 0x48,0x0f,0x45,0xc8, 0xb8,42,0,0,0, 0xba,36,0,0,0,
        0x48,0x0f,0x44,0xc2, 0x48,0x8d,0x35,-1,-1,-1,-1,
        0x48,0x8d,0x3d,-1,-1,-1,-1, 0x48,0x0f,0x45,0xfe,
        0xbe,30,0,0,0, 0x48,0x0f,0x45,0xf2, 0x41,0x80,0xbe,0x8c,0,0,0,0,
        0x48,0x0f,0x44,0xf9, 0x48,0x0f,0x44,0xf0,
        0x49,0xc7,0x07,0xff,0xff,0xff,0xff, 0x49,0xc7,0x47,0x30,0xff,0xff,0xff,0xff,
        0x49,0x89,0x7f,0x38, 0x49,0x89,0x77,0x40};
    if (!matches(elf.bytes, start.offset, pattern) ||
        !elf.function_contains(start.address, pattern.size(), "resolve_edge_tls_config"))
        fail("unrecognized MASQUE pointer/length selection instructions");
    const std::array<std::uint64_t, 4> relative_offsets{7, 0, 41, 34};
    for (std::size_t i = 0; i < found.size(); ++i) {
        const auto refs = references(elf, found[i].address);
        if (refs.size() != 1 || refs.front().offset != start.offset + relative_offsets[i])
            fail("unexpected additional MASQUE code reference");
        for (const auto& item : elf.relocations)
            if (item.second.target >= found[i].address && item.second.target < found[i].address + found[i].text.size())
                fail("unexpected MASQUE data reference");
    }
    reject_extra_references(elf, std::vector<Host>(found.begin(), found.end()), replacement.size());
    for (const auto& host : found) overwrite(result, host, replacement);
    for (const auto offset : {21u, 26u, 53u}) put(result, start.offset + offset, replacement.size(), 4);
}

void repoint_lea(Bytes& bytes, const Lea& lea, std::uint64_t target) {
    if (target > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) ||
        lea.address > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max()) - 7)
        fail("RIP-relative address overflow");
    const auto displacement = static_cast<std::int64_t>(target) - static_cast<std::int64_t>(lea.address + 7);
    if (displacement < std::numeric_limits<std::int32_t>::min() || displacement > std::numeric_limits<std::int32_t>::max())
        fail("new hostname lies outside RIP-relative addressing range");
    put(bytes, lea.offset + 3, static_cast<std::uint64_t>(displacement), 4);
}

// Verify that the pointer and length arrays are loaded with the same index.
// Linux keeps these arrays in different sections, unlike the Windows layout.
std::set<std::uint64_t> paired_lengths(const Elf& elf, std::uint64_t pointer_array,
                                     const std::array<Host, 3>& found) {
    std::set<std::uint64_t> result;
    std::map<std::uint64_t, std::set<std::uint64_t>> consumed_references;
    const auto refs = references(elf, pointer_array);
    if (refs.empty()) fail("registration pointer array has no verified code references");
    const std::vector<int> pattern{
        0x48,0x8d,0x05,-1,-1,-1,-1, 0x48,0x8b,0x1c,0xc8,
        0x48,0x8d,0x05,-1,-1,-1,-1, 0x4c,0x8b,0x3c,0xc8};
    for (const auto& ref : refs) {
        bool verified = false;
        for (const auto delta : {0u, 11u}) {
            if (ref.offset < delta || ref.address < delta) continue;
            const auto offset = ref.offset - delta;
            const auto address = ref.address - delta;
            if (!matches(elf.bytes, offset, pattern) || !elf.function_contains(address, pattern.size(), "warp_api_client")) continue;
            const auto other_offset = offset + (delta == 0 ? 11 : 0);
            const auto other = std::find_if(elf.leas.begin(), elf.leas.end(), [&](const Lea& lea) { return lea.offset == other_offset; });
            if (other == elf.leas.end()) continue;
            const auto& section = elf.section_at(other->target, 24);
            if (!section.data()) continue;
            const auto length_offset = elf.file_offset(other->target, 24);
            bool lengths_match = true;
            for (std::size_t i = 0; i < found.size(); ++i)
                if (integer(elf.bytes, length_offset + i * 8, 8) != found[i].text.size()) lengths_match = false;
            if (!lengths_match) continue;
            result.insert(length_offset);
            consumed_references[other->target].insert(other->offset);
            verified = true;
        }
        if (!verified) fail("unrecognized registration array indexing instructions");
    }
    for (const auto& item : consumed_references) {
        for (const auto& ref : references(elf, item.first))
            if (!item.second.count(ref.offset)) fail("registration length array has an additional unverified code reference");
        for (const auto& ref : elf.relocations)
            if (ref.second.target == item.first) fail("registration length array has an unverified data reference");
    }
    return result;
}

void patch_registration(const Elf& elf, Bytes& result, const std::string& requested) {
    const auto found = unique_hosts<3>(hosts(elf, registration_names), "registration");
    const auto& consumer = found[0];
    if (requested.empty()) fail("registration hostname is empty");
    auto replacement = requested;
    if (replacement.back() != '.') replacement += '.';
    std::uint64_t target = consumer.address;
    bool reuse = false;
    for (const auto& host : found) {
        if (host.text == replacement) { target = host.address; reuse = target != consumer.address; break; }
    }
    if (!reuse && replacement.size() > consumer.text.size()) replacement = requested;
    if (!reuse && replacement.size() > consumer.text.size())
        fail("registration literal is packed; use at most " + std::to_string(consumer.text.size()) +
             " bytes or an existing api.devices.cloudflare.com / api.devices.fed.cloudflare.com literal");

    const auto refs = references(elf, consumer.address);
    if (refs.size() != 2) fail("expected two direct registration hostname references");
    std::set<std::uint64_t> immediate_offsets;
    for (const auto& ref : refs) {
        const auto length = static_cast<int>(consumer.text.size());
        const std::vector<int> before{0x41,0xbc,length,0,0,0,0x48,0x8d,0x1d,-1,-1,-1,-1};
        const std::vector<int> after{0x48,0x8d,0x2d,-1,-1,-1,-1,0x41,0xbc,length,0,0,0};
        if (ref.offset >= 6 && ref.address >= 6 && matches(elf.bytes, ref.offset - 6, before) &&
            elf.function_contains(ref.address - 6, before.size(), "ApiEndpointConfig")) {
            immediate_offsets.insert(ref.offset - 4);
        } else if (matches(elf.bytes, ref.offset, after) && elf.function_contains(ref.address, after.size(), "get_client_inner")) {
            immediate_offsets.insert(ref.offset + 9);
        } else {
            fail("unrecognized registration hostname/length instructions");
        }
    }

    std::vector<Relocation> consumer_relocations;
    for (const auto& item : elf.relocations)
        if (item.second.target == consumer.address) consumer_relocations.push_back(item.second);
    if (consumer_relocations.size() != 2) fail("expected two relocated registration hostname references");
    std::set<std::uint64_t> length_offsets;
    unsigned fat_pointers = 0, pointer_arrays = 0;
    for (const auto& relocation : consumer_relocations) {
        const auto offset = elf.file_offset(relocation.address, 16);
        if (!elf.section_at(relocation.address, 16).data()) fail("registration relocation is not in a data section");
        if (integer(elf.bytes, offset + 8, 8) == consumer.text.size() && offset >= 8 &&
            integer(elf.bytes, offset - 8, 8) == std::numeric_limits<std::uint64_t>::max()) {
            length_offsets.insert(offset + 8);
            ++fat_pointers;
            continue;
        }
        bool array_matches = true;
        for (std::size_t i = 0; i < found.size(); ++i) {
            const auto ref = elf.relocations.find(relocation.address + i * 8);
            if (ref == elf.relocations.end() || ref->second.target != found[i].address) array_matches = false;
        }
        if (!array_matches) fail("unrecognized registration data reference");
        const auto paired = paired_lengths(elf, relocation.address, found);
        length_offsets.insert(paired.begin(), paired.end());
        ++pointer_arrays;
    }
    if (fat_pointers != 1 || pointer_arrays != 1 || length_offsets.size() != 2)
        fail("unverified registration slice or separate length array");

    reject_extra_references(elf, {consumer}, replacement.size());
    // All registration validation completes before its output bytes change.
    if (!reuse) overwrite(result, consumer, replacement);
    for (const auto offset : immediate_offsets) put(result, offset, replacement.size(), 4);
    for (const auto offset : length_offsets) put(result, offset, replacement.size(), 8);
    if (reuse) {
        for (const auto& ref : refs) repoint_lea(result, ref, target);
        for (const auto& ref : consumer_relocations) put(result, ref.entry_offset + 16, target, 8);
    }
}

} // namespace

Inspection inspect_elf(const Bytes& data) {
    const Elf elf(data);
    return inspection(elf);
}

PatchResult patch_elf(const Bytes& data, const PatchOptions& options) {
    if (!options.masque_host && !options.reg_api_host) {
        throw std::runtime_error("Neither MASQUE SNI nor Registration API hostname was provided.");
    }
    Elf elf(data);
    elf.analyze();
    PatchResult result{data, inspection(elf)};
    if (options.masque_host) patch_masque(elf, result.bytes, *options.masque_host);
    if (options.reg_api_host) patch_registration(elf, result.bytes, *options.reg_api_host);
    result.inspection.notes.push_back("Compiler layouts verified in Linux amd64 WARP 2026.8.2100.0 and 2026.8.2110.0; no tunnel connectivity test was performed.");
    return result;
}


} // namespace elf_impl

Inspection inspect_elf(const Bytes& data) {
    return elf_impl::inspect_elf(data);
}

PatchResult patch_elf(const Bytes& data, const PatchOptions& options) {
    return elf_impl::patch_elf(data, options);
}

} // namespace warp

namespace warp {

} // namespace warp
