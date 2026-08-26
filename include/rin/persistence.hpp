#pragma once
// SQLite-backed persistence for mesh identity and trusted devices --
// the Windows analogue of Android's Room database (MeshEntity,
// TrustedDeviceEntity).
//
// Design intent: MeshEngine should be able to load a previously-created
// identity on startup instead of always hitting the first-launch
// chooser, and every identity/trust-list mutation (create_initial_mesh,
// complete_join_handshake, revoke_device, a new peer becoming trusted)
// should be durable across restarts.
//
// SQLite chosen to mirror Android's storage choice (Room sits on top of
// SQLite) rather than for any Windows-specific reason -- a single-file
// embedded database with no server process fits the project's whole
// "no server in the middle" philosophy (doc §01) as well on the desktop
// side as Room does on mobile.
//
// This module knows nothing about crypto or transport -- it only reads
// and writes plain structs. MeshEngine owns deciding *when* to persist;
// this module owns *how*.

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

struct sqlite3;  // fwd-declare to avoid leaking <sqlite3.h> into every includer

namespace rin {

struct MeshIdentity;   // from mesh_engine.hpp
struct TrustedDevice;  // from mesh_engine.hpp

class PersistenceException : public std::runtime_error {
public:
    explicit PersistenceException(const std::string& message) : std::runtime_error(message) {}
};

// Not thread-safe by design -- MeshEngine already serializes all
// identity/trust-list mutation behind its own devices_mutex_/single
// engine instance, so this class assumes single-threaded access from
// whichever thread MeshEngine chooses to persist on. If that ever
// changes, add locking here rather than assuming callers will.
class PersistenceStore {
public:
    // Opens (creating if necessary) a SQLite database at db_path and
    // ensures the mesh_identity / trusted_devices tables exist. Throws
    // PersistenceException if the file can't be opened/created or the
    // schema can't be applied -- callers should treat persistence
    // failures as non-fatal to the mesh itself (see DESIGN_NOTES.md),
    // but this constructor failing usually means a real problem (bad
    // path, disk full, corrupt file) worth surfacing loudly once.
    explicit PersistenceStore(const std::string& db_path);
    ~PersistenceStore();

    PersistenceStore(const PersistenceStore&) = delete;
    PersistenceStore& operator=(const PersistenceStore&) = delete;

    // -- Identity ---------------------------------------------------
    // There is exactly one identity row, matching Android's
    // MeshEntity(id = 1) singleton-row convention.
    void save_identity(const MeshIdentity& identity);
    std::optional<MeshIdentity> load_identity();
    void clear_identity();  // used by a future "forget this mesh" flow, not yet exposed in the UI

    // -- Trusted devices -----------------------------------------------
    void upsert_device(const TrustedDevice& device);
    void remove_device(const std::string& public_key);
    std::vector<TrustedDevice> load_all_devices();
    void clear_all_devices();

    // Default path: %APPDATA%/Rin/mesh.db on Windows, ~/.rin/mesh.db
    // elsewhere (used by the console/GUI shells so both agree on where
    // state lives without either hardcoding the other's convention).
    static std::string default_db_path();

private:
    void apply_schema();

    sqlite3* db_ = nullptr;
    std::string db_path_;
};

}  // namespace rin
