// Rin Windows -- GUI entry point.
#ifdef _WIN32

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <asio.hpp>

#include "rin/mesh_engine.hpp"
#include "rin/win32_shell.hpp"

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    asio::io_context io;
    rin::MeshEngine  engine(io);
    rin::Win32Shell  shell(engine);
    return shell.run(hInstance);
}

#endif // _WIN32
