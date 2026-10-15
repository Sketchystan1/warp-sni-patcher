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

// Native Mach-O backend. Layouts verified against Cloudflare WARP 2026.8.2110.0.
// All edits are planned in memory; unsupported compiler layouts fail closed.


#ifdef WARP_HAS_CAPSTONE
#include <capstone/capstone.h>
#endif

#include <sstream>


namespace warp {
namespace macho_impl {
using namespace warp;

namespace {
using U = std::uint64_t;
void need(bool ok, const std::string &msg) {
    if (!ok)
        throw std::runtime_error("Mach-O: " + msg);
}
U read(const Bytes &b, U p, unsigned n, bool be = false) {
    need(n <= 8 && p <= b.size() && n <= b.size() - p, "truncated structure");
    U x = 0;
    for (unsigned i = 0; i < n; ++i)
        x |= U(b[p + i]) << (8 * (be ? n - i - 1 : i));
    return x;
}
void write(Bytes &b, U p, U x, unsigned n) {
    need(p <= b.size() && n <= b.size() - p, "write outside binary");
    for (unsigned i = 0; i < n; ++i)
        b[p + i] = std::uint8_t(x >> (8 * i));
}
std::string fixed_name(const Bytes &b, U p) {
    need(p <= b.size() && 16 <= b.size() - p, "truncated section name");
    std::string r;
    for (unsigned i = 0; i < 16 && b[p + i]; ++i)
        r += char(b[p + i]);
    return r;
}
struct Section {
    U address, size, offset;
    std::uint32_t flags;
    std::string name;
    bool code() const { return (flags & 0x80000400u) != 0; }
};
struct Segment {
    U address, vmsize, offset, size;
};
struct Slice {
    U offset, size, base = 0;
    bool arm;
    std::vector<Section> sections;
    std::vector<Segment> segments;
    std::map<std::uint32_t, std::pair<U, U>> commands;
    std::vector<U> functions;
    const Section *section(U p) const {
        for (const auto &s : sections)
            if (s.offset <= p && p - s.offset < s.size)
                return &s;
        return nullptr;
    }
    U file(U va) const {
        for (const auto &s : sections)
            if (s.address <= va && va - s.address < s.size)
                return s.offset + va - s.address;
        throw std::runtime_error("Mach-O: address is not file-backed");
    }
    U address(U p) const {
        auto s = section(p);
        need(s != nullptr, "offset is not in a section");
        return s->address + p - s->offset;
    }
    std::string arch() const { return arm ? "arm64" : "x86_64"; }
};
std::pair<U, U> payload(const Bytes &b, const Slice &s, std::uint32_t cmd) {
    auto it = s.commands.find(cmd);
    need(it != s.commands.end(), "required load command is missing");
    need(it->second.second >= 16, "truncated link-edit command");
    U off = read(b, it->second.first + 8, 4), size = read(b, it->second.first + 12, 4);
    need(off <= s.size && size <= s.size - off, "link-edit data outside slice");
    return {s.offset + off, size};
}
Slice thin(const Bytes &b, U off, U size) {
    need(off <= b.size() && size <= b.size() - off && size >= 32, "invalid slice bounds");
    need(read(b, off, 4) == 0xfeedfacf, "expected little-endian 64-bit Mach-O");
    U cpu = read(b, off + 4, 4), sub = read(b, off + 8, 4);
    need(cpu == 0x1000007 || (cpu == 0x100000c && (sub & 0xffffff) == 0),
         "only x86_64 and arm64 are supported");
    need(read(b, off + 12, 4) == 2, "expected an executable");
    U count = read(b, off + 16, 4), cmdsize = read(b, off + 20, 4);
    need(cmdsize <= size - 32 && count <= cmdsize / 8, "invalid load-command size");
    Slice s;
    s.offset = off;
    s.size = size;
    s.arm = (cpu == 0x100000c);
    U p = off + 32, end = p + cmdsize;
    unsigned bases = 0;
    for (U i = 0; i < count; ++i) {
        U cmd = read(b, p, 4), n = read(b, p + 4, 4);
        need(n >= 8 && n % 8 == 0 && n <= end - p, "invalid load command");
        if (cmd == 0x19) {
            need(n >= 72, "truncated segment");
            U va = read(b, p + 24, 8), vs = read(b, p + 32, 8), fo = read(b, p + 40, 8),
              fs = read(b, p + 48, 8), ns = read(b, p + 64, 4);
            need(fo <= size && fs <= size - fo && ns <= (n - 72) / 80, "invalid segment bounds");
            need(va <= std::numeric_limits<U>::max() - vs, "segment address overflow");
            need(va + vs <= U(std::numeric_limits<std::int64_t>::max()) - 0x100000000ULL,
                 "unsupported high virtual address");
            s.segments.push_back({va, vs, off + fo, fs});
            if (fo == 0 && fs) {
                s.base = va;
                ++bases;
            }
            for (U j = 0; j < ns; ++j) {
                U q = p + 72 + 80 * j, sa = read(b, q + 32, 8), ss = read(b, q + 40, 8),
                  so = read(b, q + 48, 4);
                auto flags = std::uint32_t(read(b, q + 64, 4));
                unsigned type = flags & 0xff;
                if (type == 1 || type == 0xc || type == 0x12)
                    continue;
                need(so >= fo && so - fo <= fs && ss <= fs - (so - fo), "section outside segment");
                need(sa >= va && sa - va <= vs && ss <= vs - (sa - va), "invalid section address");
                need(sa - va == so - fo, "section address disagrees with segment file mapping");
                s.sections.push_back({sa, ss, off + so, flags, fixed_name(b, q)});
            }
        } else {
            need(s.commands.emplace(std::uint32_t(cmd), std::make_pair(p, n)).second ||
                     cmd == 0xc || cmd == 0x80000018 || cmd == 0x8000001c,
                 "duplicate load command");
        }
        if (cmd == 0x21 || cmd == 0x2c)
            need(n >= 20 && read(b, p + 16, 4) == 0, "encrypted binaries are unsupported");
        p += n;
    }
    need(p == end && bases == 1, "inconsistent Mach-O image layout");
    auto sections = s.sections;
    std::sort(sections.begin(), sections.end(),
              [](auto &a, auto &c) { return a.offset < c.offset; });
    for (size_t i = 1; i < sections.size(); ++i)
        need(sections[i - 1].size <= sections[i].offset - sections[i - 1].offset,
             "overlapping sections");
    std::sort(sections.begin(), sections.end(),
              [](auto &a, auto &c) { return a.address < c.address; });
    for (size_t i = 1; i < sections.size(); ++i)
        need(sections[i - 1].size <= sections[i].address - sections[i - 1].address,
             "overlapping section addresses");
    need(std::any_of(s.sections.begin(), s.sections.end(), [](auto &a) { return a.code(); }),
         "missing executable section");
    auto f = payload(b, s, 0x26);
    U fp = f.first, fe = fp + f.second, addr = s.base;
    bool term = false;
    while (fp < fe) {
        U delta = 0;
        unsigned shift = 0;
        std::uint8_t v;
        do {
            need(fp < fe && shift < 64, "invalid function-start ULEB128");
            v = b[fp++];
            need(shift != 63 || (v & 0x7e) == 0, "function-start overflow");
            delta |= U(v & 127) << shift;
            shift += 7;
        } while (v & 128);
        if (!delta) {
            term = true;
            break;
        }
        need(delta <= std::numeric_limits<U>::max() - addr, "function-start address overflow");
        addr += delta;
        U loc = s.file(addr);
        auto sec = s.section(loc);
        need(sec && sec->code(), "function start outside code");
        s.functions.push_back(addr);
    }
    need(term && !s.functions.empty(), "missing terminated function starts");
    return s;
}
std::vector<Slice> slices(const Bytes &b) {
    need(b.size() >= 4, "file too small");
    if (read(b, 0, 4) == 0xfeedfacf)
        return {thin(b, 0, b.size())};
    U magic = read(b, 0, 4, true);
    bool wide = (magic == 0xcafebabf || magic == 0xbfbafeca);
    bool be = (magic == 0xcafebabe || magic == 0xcafebabf);
    need(be || magic == 0xbebafeca || magic == 0xbfbafeca, "not a supported universal Mach-O");
    U n = read(b, 4, 4, be), stride = wide ? 32 : 20;
    need(n && n <= 16 && 8 + n * stride <= b.size(), "invalid universal header");
    std::vector<Slice> result;
    std::set<bool> arch;
    for (U i = 0; i < n; ++i) {
        U p = 8 + i * stride, cpu = read(b, p, 4, be), sub = read(b, p + 4, 4, be);
        U off = read(b, p + 8, wide ? 8 : 4, be),
          size = read(b, p + (wide ? 16 : 12), wide ? 8 : 4, be),
          align = read(b, p + (wide ? 24 : 16), 4, be);
        need(align <= 30 && off % (U(1) << align) == 0 && off >= 8 + n * stride,
             "invalid slice alignment");
        Slice s = thin(b, off, size);
        need(read(b, off + 4, 4) == cpu && read(b, off + 8, 4) == sub,
             "architecture header mismatch");
        for (const auto &r : result)
            need(off + size <= r.offset || r.offset + r.size <= off, "overlapping slices");
        need(arch.insert(s.arm).second, "duplicate architecture");
        result.push_back(std::move(s));
    }
    return result;
}
const std::array<std::string, 7> names = {
    {"consumer-masque.cloudflareclient.com", "consumer-masque-proxy.cloudflareclient.com",
     "zt-masque.cloudflareclient.com", "zt-masque-proxy.cloudflareclient.com",
     "api.cloudflareclient.com.", "api.devices.cloudflare.com.",
     "api.devices.fed.cloudflare.com."}};
struct Host {
    U offset, address;
    std::string text;
};
std::vector<Host> hosts(const Bytes &b, const Slice &s) {
    std::vector<Host> out;
    for (const auto &name : names) {
        std::vector<U> found;
        for (const auto &sec : s.sections)
            if (!sec.code()) {
                auto begin = b.begin() + sec.offset, end = begin + sec.size;
                while (true) {
                    auto it = std::search(begin, end, name.begin(), name.end());
                    if (it == end)
                        break;
                    U p = U(it - b.begin());
                    if (name.back() == '.' || p + name.size() == sec.offset + sec.size ||
                        b[p + name.size()] != '.')
                        found.push_back(p);
                    begin = it + name.size();
                }
            }
        need(found.size() == 1,
             "expected exactly one pristine literal for " + name + " in " + s.arch());
        out.push_back({found[0], s.address(found[0]), name});
    }
    return out;
}
// Enumerate actual dyld chains: upper bits are metadata, not part of an address.
std::map<U, U> fixups(const Bytes &b, const Slice &s) {
    auto pl = payload(b, s, 0x80000034);
    U start = pl.first, end = start + pl.second;
    need(pl.second >= 28 && read(b, start, 4) == 0, "unsupported chained-fixups header");
    U delta = read(b, start + 4, 4);
    need(delta <= pl.second && pl.second - delta >= 4, "bad fixup starts");
    U si = start + delta, n = read(b, si, 4);
    need(n == s.segments.size() && n <= (end - si - 4) / 4, "bad fixup segment count");
    std::map<U, U> out;
    for (U i = 0; i < n; ++i) {
        U rel = read(b, si + 4 + 4 * i, 4);
        if (!rel)
            continue;
        need(rel <= end - si && end - si - rel >= 22, "bad fixup segment offset");
        U p = si + rel;
        U sz = read(b, p, 4), pagesize = read(b, p + 4, 2), fmt = read(b, p + 6, 2),
          seg_off = read(b, p + 8, 8), pc = read(b, p + 20, 2);
        need(sz >= 22 && sz <= end - p && pc <= (sz - 22) / 2, "bad fixup segment size");
        need(fmt == 6 && (pagesize == 4096 || pagesize == 16384),
             "only DYLD_CHAINED_PTR_64_OFFSET is supported");
        const auto &seg = s.segments[i];
        need(seg.address >= s.base && seg_off == seg.address - s.base,
             "fixup segment address mismatch");
        need(pc <= ((seg.size + pagesize - 1) / pagesize), "fixup pages outside segment");
        for (U j = 0; j < pc; ++j) {
            U ps = read(b, p + 22 + 2 * j, 2);
            if (ps == 0xffff)
                continue;
            need((ps & 0x8000) == 0 && ps < pagesize, "multi-start fixup pages are unsupported");
            U pos = seg.offset + j * pagesize + ps,
              pageend = std::min(seg.offset + seg.size, seg.offset + (j + 1) * pagesize);
            for (;;) {
                need(pos <= pageend && pageend - pos >= 8 && pos % 4 == 0,
                     "fixup chain outside page");
                U v = read(b, pos, 8);
                // Bind entries are loader imports. Rebase entries contain image-relative target36.
                if (!(v >> 63)) {
                    need(((v >> 36) & 0x7fff) == 0,
                         "unsupported high/reserved bits in chained pointer");
                    need(out.emplace(pos, s.base + (v & 0xfffffffffULL)).second,
                         "cyclic/duplicate fixup");
                }
                U next = (v >> 51) & 0xfff;
                if (!next)
                    break;
                need(4 * next <= pageend - pos, "fixup chain overflow");
                pos += 4 * next;
            }
        }
    }
    return out;
}
#if defined(WARP_HAS_CAPSTONE)
struct Decoder {
    csh handle = 0;
    cs_insn *ins = nullptr;
    explicit Decoder(bool arm) {
        need(cs_open(arm ? CS_ARCH_ARM64 : CS_ARCH_X86, arm ? CS_MODE_ARM : CS_MODE_64, &handle) ==
                 CS_ERR_OK,
             "cannot initialize Capstone");
        ins = cs_malloc(handle);
        need(ins != nullptr, "cannot allocate disassembler");
    }
    ~Decoder() {
        if (ins)
            cs_free(ins, 1);
        if (handle)
            cs_close(&handle);
    }
    Decoder(const Decoder &) = delete;
    Decoder &operator=(const Decoder &) = delete;
    bool boundary(const Bytes &b, const Slice &s, U off) {
        U va = s.address(off);
        auto it = std::upper_bound(s.functions.begin(), s.functions.end(), va);
        if (it == s.functions.begin())
            return false;
        --it;
        U addr = *it, p = s.file(addr);
        auto sec = s.section(p);
        need(sec && sec->code(), "invalid function start");
        if (s.section(off) != sec || va - addr > 4 * 1024 * 1024)
            return false;
        const std::uint8_t *ptr = b.data() + p;
        size_t remaining = size_t(sec->offset + sec->size - p);
        while (addr < va) {
            if (!cs_disasm_iter(handle, &ptr, &remaining, &addr, ins))
                return false;
        }
        return addr == va;
    }
};
#else
struct Decoder {
    explicit Decoder(bool) {}
    bool boundary(const Bytes &, const Slice &, U) {
        throw std::runtime_error("Mach-O instruction inspection requires Capstone engine (available on macOS)");
    }
};
#endif
struct Ref {
    U offset, target;
    unsigned span;
};
std::int64_t sign_extend(U v, unsigned n) {
    return (v & (U(1) << (n - 1))) ? std::int64_t(v) - std::int64_t(U(1) << n) : std::int64_t(v);
}
std::vector<Ref> references(const Bytes &b, const Slice &s, const std::set<U> &targets,
                            Decoder &decoder) {
    std::vector<Ref> result;
    for (const auto &sec : s.sections)
        if (sec.code()) {
            U end = sec.offset + sec.size;
            for (U p = sec.offset; p + (s.arm ? 4 : 7) <= end; p += s.arm ? 4 : 1) {
                U target = 0;
                unsigned span = 0;
                if (s.arm) {
                    U a = read(b, p, 4);
                    if ((a & 0x9f000000) == 0x10000000) {
                        target = U(std::int64_t(s.address(p)) +
                                   sign_extend(((a >> 29) & 3) | (((a >> 5) & 0x7ffff) << 2), 21));
                        span = 4;
                    } else if ((a & 0x9f000000) == 0x90000000) {
                        // Find unsupported separated pairs too, so a new compiler cannot silently
                        // evade reference accounting.
                        for (U q = p + 4; q + 4 <= end && q <= p + 32; q += 4) {
                            U c = read(b, q, 4);
                            if ((c & 0xffc00000) != 0x91000000 || ((c >> 5) & 31) != (a & 31))
                                continue;
                            auto delta =
                                sign_extend(((a >> 29) & 3) | (((a >> 5) & 0x7ffff) << 2), 21) *
                                4096;
                            U t =
                                U(std::int64_t((sec.address + p - sec.offset) & ~U(4095)) + delta) +
                                ((c >> 10) & 4095);
                            if (targets.count(t)) {
                                target = t;
                                span = unsigned(q - p + 4);
                                break;
                            }
                            if ((c & 31) == (a & 31))
                                break; // ADD replaced this page base.
                        }
                    }
                } else if ((b[p] & 0xf8) == 0x48 && b[p + 1] == 0x8d && (b[p + 2] & 0xc7) == 5) {
                    target = U(std::int64_t(sec.address + p - sec.offset + 7) +
                               sign_extend(read(b, p + 3, 4), 32));
                    span = 7;
                }
                if (span && targets.count(target) && decoder.boundary(b, s, p)) {
                    need(!s.arm || span == 8, "unsupported ARM address-loading sequence");
                    result.push_back({p, target, span});
                }
            }
        }
    return result;
}
// '?' masks only relocation/immediate address fields; all control/data-flow bytes match.
bool match(const Bytes &b, U p, const std::string &pattern) {
    std::istringstream in(pattern);
    std::string token;
    U i = 0;
    while (in >> token) {
        if (p + i >= b.size())
            return false;
        if (token != "??" && b[p + i] != std::stoul(token, nullptr, 16))
            return false;
        ++i;
    }
    return true;
}
bool words(const Bytes &b, U p, const std::vector<std::pair<std::uint32_t, std::uint32_t>> &items) {
    if (p > b.size() || items.size() > (b.size() - p) / 4)
        return false;
    for (size_t i = 0; i < items.size(); ++i)
        if ((read(b, p + 4 * i, 4) & items[i].second) != items[i].first)
            return false;
    return true;
}
std::pair<std::uint32_t, std::uint32_t> exact(std::uint32_t v) { return {v, 0xffffffff}; }
std::pair<std::uint32_t, std::uint32_t> adrp(unsigned reg) {
    return {0x90000000u | reg, 0x9f00001f};
}
std::pair<std::uint32_t, std::uint32_t> add(unsigned reg) {
    return {0x91000000u | (reg << 5) | reg, 0xffc003ff};
}
void length_arm(Bytes &b, U p, size_t length) {
    U old = read(b, p, 4);
    need((old & 0xffe00000) == 0x52800000 && length < 65536, "unsupported ARM length immediate");
    write(b, p, (old & ~U(0x1fffe0)) | (U(length) << 5), 4);
}
void retarget(Bytes &out, const Bytes &original, const Slice &s, U p, U target) {
    if (s.arm) {
        U a = read(original, p, 4), c = read(original, p + 4, 4);
        auto pages =
            (std::int64_t(target & ~U(4095)) - std::int64_t(s.address(p) & ~U(4095))) / 4096;
        need(pages >= -(1 << 20) && pages < (1 << 20), "new ARM address out of range");
        U imm = U(pages) & 0x1fffff;
        write(out, p, (a & 0x9f00001f) | ((imm & 3) << 29) | ((imm >> 2) << 5), 4);
        write(out, p + 4, (c & ~U(0x3ffc00)) | ((target & 4095) << 10), 4);
    } else {
        auto disp = std::int64_t(target) - std::int64_t(s.address(p) + 7);
        need(disp >= std::numeric_limits<std::int32_t>::min() &&
                 disp <= std::numeric_limits<std::int32_t>::max(),
             "new x86 address out of range");
        write(out, p + 3, U(disp), 4);
    }
}
struct Layout {
    std::vector<Host> host;
    std::map<U, U> pointers;
    std::vector<Ref> refs;
    U selector = 0, fat = 0, ptr_array = 0, len_array = 0;
    std::vector<U> reg_refs, reg_lengths;
};
bool code_span(const Slice &s, U offset, U size) {
    auto section = s.section(offset);
    return section && section->code() && size <= section->offset + section->size - offset;
}
Layout layout(const Bytes &b, const Slice &s) {
    Layout l;
    l.host = hosts(b, s);
    l.pointers = fixups(b, s);
    auto protected_host = [&](U address) {
        return std::any_of(l.host.begin(), l.host.begin() + 5, [&](const Host &h) {
            return h.address <= address && address - h.address < h.text.size();
        });
    };
    for (const auto &pointer : l.pointers)
        if (protected_host(pointer.second))
            need(std::any_of(l.host.begin(), l.host.begin() + 5,
                             [&](const Host &h) { return h.address == pointer.second; }),
                 "a chained pointer shares an overwritten hostname prefix");
    // Unchained absolute pointers are not handled by the verified compiler patterns.
    // Examine every byte alignment, since Rust packed constants need not be aligned.
    for (const auto &section : s.sections) {
        if (section.code() || section.size < 8)
            continue;
        U value = read(b, section.offset, 8);
        for (U delta = 0; delta <= section.size - 8; ++delta) {
            need(!protected_host(value), "untracked absolute pointer into a hostname literal");
            if (delta < section.size - 8)
                value = (value >> 8) | (U(b[section.offset + delta + 8]) << 56);
        }
    }
    std::vector<U> consumer;
    for (const auto &p : l.pointers) {
        for (size_t i = 0; i < 4; ++i)
            need(p.second != l.host[i].address, "unexpected MASQUE data pointer");
        if (p.second == l.host[4].address)
            consumer.push_back(p.first);
    }
    need(consumer.size() == 2, "expected API fat pointer and parallel pointer array");
    for (U p : consumer) {
        auto sec = s.section(p);
        need(sec && !sec->code(), "API pointer outside data");
        if (p + 16 <= sec->offset + sec->size && read(b, p + 8, 8) == 25 &&
            !l.pointers.count(p + 8)) {
            need(l.fat == 0 && p >= sec->offset + 8 && read(b, p - 8, 8) == ~U(0),
                 "invalid API fat-pointer record");
            l.fat = p;
        } else {
            need(l.ptr_array == 0 && p + 24 <= sec->offset + sec->size,
                 "ambiguous API pointer array");
            for (size_t j = 0; j < 3; ++j) {
                auto it = l.pointers.find(p + 8 * j);
                need(it != l.pointers.end() && it->second == l.host[j + 4].address,
                     "unverified API pointer-array entries");
            }
            l.ptr_array = p;
        }
    }
    need(l.fat && l.ptr_array, "API data references could not be verified");
    // The three-length array is in __TEXT; it is not adjacent to __DATA_CONST pointers.
    Bytes lens(24);
    write(lens, 0, 25, 8);
    write(lens, 8, 27, 8);
    write(lens, 16, 31, 8);
    for (const auto &sec : s.sections)
        if (!sec.code()) {
            auto begin = b.begin() + sec.offset, end = begin + sec.size;
            for (;;) {
                auto it = std::search(begin, end, lens.begin(), lens.end());
                if (it == end)
                    break;
                need(l.len_array == 0, "ambiguous API length array");
                l.len_array = U(it - b.begin());
                begin = it + lens.size();
            }
        }
    need(l.len_array != 0, "API length array not found");
    std::set<U> targets;
    for (const auto &h : l.host)
        targets.insert(h.address);
    for (size_t i = 0; i < 5; ++i)
        for (U delta = 1; delta < l.host[i].text.size(); ++delta)
            targets.insert(l.host[i].address + delta);
    U ptrva = s.address(l.ptr_array), lenva = s.address(l.len_array);
    targets.insert(ptrva);
    targets.insert(lenva);
    Decoder decoder(s.arm);
    l.refs = references(b, s, targets, decoder);
    for (const auto &ref : l.refs)
        if (protected_host(ref.target))
            need(std::any_of(l.host.begin(), l.host.begin() + 5,
                             [&](const Host &h) { return h.address == ref.target; }),
                 "a code reference shares an overwritten hostname prefix");
    auto refs_to = [&](U target) {
        std::vector<U> r;
        for (auto &v : l.refs)
            if (v.target == target)
                r.push_back(v.offset);
        return r;
    };
    auto ref_at = [&](U offset, U target) {
        return std::any_of(l.refs.begin(), l.refs.end(),
                           [&](auto &r) { return r.offset == offset && r.target == target; });
    };
    for (size_t i = 0; i < 4; ++i)
        need(refs_to(l.host[i].address).size() == 1, "unexpected MASQUE reference count");
    l.selector = refs_to(l.host[s.arm ? 0 : 1].address)[0];
    U p = l.selector;
    need(code_span(s, p, s.arm ? 92 : 100), "MASQUE selector leaves its code section");
    if (!s.arm) {
        need(match(b, p,
                   "48 8d 05 ?? ?? ?? ?? 48 8d 0d ?? ?? ?? ?? 84 db 48 0f 45 c8 b8 2a 00 00 00 ba "
                   "24 00 00 00 48 0f 44 c2 48 8d 35 ?? ?? ?? ?? 48 8d 3d ?? ?? ?? ?? 48 0f 45 fe "
                   "be 1e 00 00 00 48 0f 45 f2 41 80 be 8c 00 00 00 00 48 0f 44 f9 48 0f 44 f0 49 "
                   "c7 07 ff ff ff ff 49 c7 47 30 ff ff ff ff 49 89 7f 38 49 89 77 40"),
             "unrecognized x86 MASQUE selector");
        need(ref_at(p + 7, l.host[0].address) && ref_at(p + 34, l.host[3].address) &&
                 ref_at(p + 41, l.host[2].address),
             "x86 selector points at unexpected strings");
    } else {
        need(words(b, p, {adrp(9),           add(9),
                          adrp(10),          add(10),
                          exact(0x7100027f), exact(0x9a891149),
                          exact(0x5280048a), exact(0x5280054b),
                          adrp(12),          add(12),
                          adrp(13),          add(13),
                          exact(0x9a8a116b), exact(0x9a8c11ac),
                          exact(0x528003cd), exact(0x9a8d114a),
                          exact(0x7100011f), exact(0x9a891188),
                          exact(0x92800009), exact(0xf90002a9),
                          exact(0x9a8b114a), exact(0xa90322a9),
                          exact(0xf90022aa)}),
             "unrecognized ARM MASQUE selector");
        need(ref_at(p + 8, l.host[1].address) && ref_at(p + 32, l.host[2].address) &&
                 ref_at(p + 40, l.host[3].address),
             "ARM selector points at unexpected strings");
    }
    // Both separate-array users must load matching indices from the proven arrays.
    auto pr = refs_to(ptrva), lr = refs_to(lenva);
    need(pr.size() == 2 && lr.size() == 2, "unexpected parallel-array reference count");
    std::set<U> consumed_lengths;
    for (U r : pr) {
        if (!s.arm) {
            U start = 0, other = 0;
            if (ref_at(r + 11, lenva)) {
                start = r;
                other = r + 11;
            } else if (r >= 11 && ref_at(r - 11, lenva)) {
                start = r - 11;
                other = r - 11;
            }
            need(start && code_span(s, start, 22) &&
                     match(b, start,
                           "48 8d 05 ?? ?? ?? ?? 48 8b 1c c8 48 8d 05 ?? ?? ?? ?? 4c 8b 3c c8"),
                 "unverified x86 parallel-array indexing");
            consumed_lengths.insert(other);
        } else {
            U other = 0;
            if (ref_at(r + 12, lenva)) {
                need(code_span(s, r, 24) && words(b, r,
                                                  {adrp(9), add(9), exact(0xf8687933), adrp(9),
                                                   add(9), exact(0xf8687934)}),
                     "unverified ARM parallel-array indexing");
                other = r + 12;
            } else if (r >= 12 && ref_at(r - 12, lenva)) {
                need(code_span(s, r - 12, 24) && words(b, r - 12,
                                                       {adrp(10), add(10), exact(0xf8697953),
                                                        adrp(10), add(10), exact(0xf8697955)}),
                     "unverified ARM parallel-array indexing");
                other = r - 12;
            }
            need(other != 0, "unpaired ARM length-array reference");
            consumed_lengths.insert(other);
        }
    }
    need(consumed_lengths.size() == 2, "unpaired API length-array references");
    l.reg_refs = refs_to(l.host[4].address);
    need(l.reg_refs.size() == 2, "unexpected direct API reference count");
    std::set<int> styles;
    for (U r : l.reg_refs) {
        if (!s.arm) {
            if (r >= 6 && code_span(s, r - 6, 15) &&
                match(b, r - 6, "41 bc 19 00 00 00 4c 8d 2d ?? ?? ?? ?? eb ??") &&
                decoder.boundary(b, s, r - 6)) {
                l.reg_lengths.push_back(r - 4);
                styles.insert(1);
            } else if (code_span(s, r, 18) &&
                       match(b, r, "48 8d 1d ?? ?? ?? ?? 41 bf 19 00 00 00 e9 ?? ?? ?? ??")) {
                l.reg_lengths.push_back(r + 9);
                styles.insert(2);
            } else
                need(false, "unrecognized x86 API string/length load");
        } else {
            if (code_span(s, r, 16) &&
                words(b, r, {adrp(26), add(26), exact(0x52800339), {0x14000000, 0xfc000000}})) {
                l.reg_lengths.push_back(r + 8);
                styles.insert(1);
            } else if (code_span(s, r, 24) && words(b, r,
                                                    {adrp(20),
                                                     add(20),
                                                     exact(0x92800016),
                                                     exact(0x52800039),
                                                     exact(0x52800335),
                                                     {0x14000000, 0xfc000000}})) {
                l.reg_lengths.push_back(r + 16);
                styles.insert(2);
            } else
                need(false, "unrecognized ARM API string/length load");
        }
    }
    need(styles.size() == 2, "duplicate API compiler patterns");
    return l;
}
Inspection summary(const std::vector<Slice> &ss) {
    Inspection i;
    i.format = "Mach-O";
    i.masque_occurrences = 4 * ss.size();
    i.registration_occurrences = ss.size();
    for (const auto &s : ss)
        i.architectures.push_back(s.arch());
    i.notes = {
        "Verified chained pointers and x86_64/arm64 compiler layouts from WARP 2026.8.2110.0.",
        "Modified executables require macOS signing and invalidate their enclosing app's vendor seal. "
        "PacketTunnel certificate requirements remain incompatible with ad-hoc signing.",
        "Registration replacements over 25 bytes must match an existing devices/federal endpoint."};
    return i;
}
} // namespace
Inspection inspect_macho(const Bytes &data) {
    auto ss = slices(data);
    for (const auto &s : ss)
        (void)layout(data, s);
    return summary(ss);
}
PatchResult patch_macho(const Bytes &data, const PatchOptions &options) {
    if (!options.masque_host && !options.reg_api_host) {
        need(false, "Neither MASQUE SNI nor Registration API hostname was provided");
    }
    if (options.masque_host) {
        ValidateHostname(*options.masque_host);
        need(options.masque_host->size() <= 30, "MASQUE hostname must fit the shortest 30-byte literal");
    }
    if (options.reg_api_host)
        ValidateHostname(*options.reg_api_host);
    auto ss = slices(data);
    std::vector<Layout> plans;
    for (const auto &s : ss)
        plans.push_back(layout(data, s));
    // Validate every architecture before returning any bytes to the caller.
    PatchResult result;
    result.bytes = data;
    result.inspection = summary(ss);
    for (size_t i = 0; i < ss.size(); ++i) {
        const auto &s = ss[i];
        const auto &l = plans[i];
        auto &out = result.bytes;
        if (options.masque_host) {
            for (size_t h = 0; h < 4; ++h)
                std::copy(options.masque_host->begin(), options.masque_host->end(),
                          out.begin() + l.host[h].offset);
            if (s.arm)
                for (U rel : {U(24), U(28), U(56)})
                    length_arm(out, l.selector + rel, options.masque_host->size());
            else
                for (U rel : {U(21), U(26), U(53)})
                    write(out, l.selector + rel, options.masque_host->size(), 4);
        }
        if (options.reg_api_host) {
            std::string replacement = *options.reg_api_host;
            if (replacement.back() != '.')
                replacement += '.';
            U target = l.host[4].address;
            bool reuse = false;
            for (size_t h = 4; h < 7; ++h)
                if (replacement == l.host[h].text) {
                    target = l.host[h].address;
                    reuse = true;
                    break;
                }
            // Keep an undotted 25-byte user hostname if a trailing dot cannot fit.
            if (!reuse && replacement.size() > 25 && options.reg_api_host->back() != '.' &&
                options.reg_api_host->size() <= 25)
                replacement = *options.reg_api_host;
            need(reuse || replacement.size() <= 25, "registration hostname exceeds the packed "
                                                    "25-byte slot and is not an existing endpoint");
            if (!reuse)
                std::copy(replacement.begin(), replacement.end(), out.begin() + l.host[4].offset);
            write(out, l.fat + 8, replacement.size(), 8);
            write(out, l.len_array, replacement.size(), 8);
            for (U p : l.reg_lengths) {
                if (s.arm)
                    length_arm(out, p, replacement.size());
                else
                    write(out, p, replacement.size(), 4);
            }
            if (target != l.host[4].address) {
                U relative = target - s.base;
                need(relative <= 0xfffffffffULL, "new chained target out of range");
                for (U p : {l.fat, l.ptr_array})
                    write(out, p, (read(data, p, 8) & ~U(0xfffffffffULL)) | relative, 8);
                for (U p : l.reg_refs)
                    retarget(out, data, s, p, target);
            }
        }
    }
    return result;
}

} // namespace macho_impl

Inspection inspect_macho(const Bytes& data) {
    return macho_impl::inspect_macho(data);
}

PatchResult patch_macho(const Bytes& data, const PatchOptions& options) {
    return macho_impl::patch_macho(data, options);
}

} // namespace warp

namespace warp {

} // namespace warp
