#pragma once

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace warp {

int RunGui(int argc, char** argv);

} // namespace warp

#ifdef _WIN32
int RunGui(HINSTANCE hInstance, int nCmdShow, int argc, char** argv);
#endif
