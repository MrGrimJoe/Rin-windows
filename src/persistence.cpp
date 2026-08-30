#include "rin/persistence.hpp"

#include <sqlite3.h>

#include <cstdlib>
#include <sstream>

#include "rin/mesh_engine.hpp"
#include "rin/protocol.hpp"

#ifdef _WIN32
// See mesh_engine.cpp for why these two defines have to come first --
// same WinSock conflict, same fix.
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <shlobj.h>
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace rin {

namespace {

[[noreturn]] void throw_sqlite_error(sqlite3* db, const std::string& context) {
    std::string msg = context + ": " + (db ? sqlite3_errmsg(db) : "no database handle");
    throw PersistenceException(msg);
}

void exec_or_throw(sqlite3* db, const std::string& sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw PersistenceException("SQL failed: " + msg + " (statement: " + sql + ")");
    }
}

// Thin RAII wrapper so every early-return/throw path below still
// finalizes the prepared statement -- sqlite3_stmt leaks are easy to
// introduce across the several error-handling branches each query needs.
class Stmt {
public:
    Stmt(sqlite3* db, const std::string& sql) {
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt_, nullptr) != SQLITE_OK) {
            throw_sqlite_error(db, "prepare failed for: " + sql);
        }
    }
    ~Stmt() { sqlite3_finalize(stmt_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    sqlite3_stmt* get() { return stmt_; }

    void bind_text(int index, const std::string& value) {
        sqlite3_bind_text(stmt_, index, value.c_str(), -1, SQLITE_TRANSIENT);
    }
    void bind_int(int index, int value) { sqlite3_bind_int(stmt_, index, value); }
    void bind_int64(int index, int64_t value) { sqlite3_bind_int64(stmt_, index, value); }
    void bind_null(int index) { sqlite3_bind_null(stmt_, index); }

    std::string column_text(int index) {
        const unsigned char* text = sqlite3_column_text(stmt_, index);
        return text ? reinterpret_cast<const char*>(text) : "";
    }
    bool column_is_null(int index) { return sqlite3_column_type(stmt_, index) == SQLITE_NULL; }
    int column_int(int index) { return sqlite3_column_int(stmt_, index); }
    int64_t column_int64(int index) { return sqlite3_column_int64(stmt_, index); }

private:
    sqlite3_stmt* stmt_ = nullptr;
};

// Serialize PlatformType/ConnectionState/TransportRail as their existing
// wire-format strings (protocol.hpp already defines these conversions
// for PacketType/TransportRail; platform/state need small local mappings
// since they're mesh_engine-only enums, not wire-protocol ones).
const char* platform_to_string(PlatformType p) {
    switch (p) {
        case PlatformType::Android: return "ANDROID";
        case PlatformType::Windows: return "WINDOWS";
        case PlatformType::Linux: return "LINUX";
        case PlatformType::MacOS: return "MACOS";
        case PlatformType::Tablet: return "TABLET";
    }
    return "WINDOWS";
}
PlatformType platform_from_string(const std::string& s) {
    if (s == "ANDROID") return PlatformType::Android;
    if (s == "LINUX") return PlatformType::Linux;
    if (s == "MACOS") return PlatformType::MacOS;
    if (s == "TABLET") return PlatformType::Tablet;
    return PlatformType::Windows;
}

const char* state_to_string(ConnectionState s) {
    switch (s) {
        case ConnectionState::Connected: return "CONNECTED";
        case ConnectionState::Active: return "ACTIVE";
        case ConnectionState::Reconnecting: return "RECONNECTING";
        case ConnectionState::Idle: return "IDLE";
        case ConnectionState::Offline: return "OFFLINE";
        case ConnectionState::Lost: return "LOST";
        case ConnectionState::Discovered: return "DISCOVERED";
        case ConnectionState::Authenticating: return "AUTHENTICATING";
    }
    return "OFFLINE";
}
ConnectionState state_from_string(const std::string& s) {
    // A device loaded from disk was, by definition, not reachable a
    // moment ago -- always load as Offline rather than trusting a
    // possibly-stale CONNECTED/ACTIVE row from the last session. The
    // real state gets re-established the moment discovery or a live
    // packet exchange happens again.
    (void)s;
    return ConnectionState::Offline;
}

}  // namespace

PersistenceStore::PersistenceStore(const std::string& db_path) : db_path_(db_path) {
    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
        std::string msg = db_ ? sqlite3_errmsg(db_) : "sqlite3_open returned null handle";
        if (db_) sqlite3_close(db_);
        db_ = nullptr;
        throw PersistenceException("could not open database at '" + db_path + "': " + msg);
    }
    exec_or_throw(db_, "PRAGMA foreign_keys = ON;");
    apply_schema();
}

PersistenceStore::~PersistenceStore() {
    if (db_) sqlite3_close(db_);
}

void PersistenceStore::apply_schema() {
    // Mirrors MeshEntity / TrustedDeviceEntity's shape closely enough
    // for a person reading both schemas side by side to recognize them
    // as the same concept, without claiming binary/file compatibility
    // with Android's Room database (different engines, different files
    // -- there's no scenario where these are the same file).
    exec_or_throw(db_, R"(
        CREATE TABLE IF NOT EXISTS mesh_identity (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            mesh_name TEXT NOT NULL,
            local_device_name TEXT NOT NULL,
            local_public_key TEXT NOT NULL,
            local_private_key TEXT NOT NULL,
            local_fingerprint TEXT NOT NULL,
            mesh_secret TEXT NOT NULL,
            port INTEGER NOT NULL
        );
    )");

    exec_or_throw(db_, R"(
        CREATE TABLE IF NOT EXISTS trusted_devices (
            public_key TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            platform TEXT NOT NULL,
            ip_address TEXT,
            port INTEGER NOT NULL,
            is_self INTEGER NOT NULL DEFAULT 0
        );
    )");
    // Deliberately NOT persisting connection_state, active_rail, or
    // latency_ms -- those are live/transient session facts, not durable
    // identity facts, and persisting a stale CONNECTED from last session
    // would be actively misleading on next launch (see
    // state_from_string's always-Offline behavior above).
}

void PersistenceStore::save_identity(const MeshIdentity& identity) {
    Stmt stmt(db_, R"(
        INSERT INTO mesh_identity
            (id, mesh_name, local_device_name, local_public_key, local_private_key,
             local_fingerprint, mesh_secret, port)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            mesh_name = excluded.mesh_name,
            local_device_name = excluded.local_device_name,
            local_public_key = excluded.local_public_key,
            local_private_key = excluded.local_private_key,
            local_fingerprint = excluded.local_fingerprint,
            mesh_secret = excluded.mesh_secret,
            port = excluded.port;
    )");
    stmt.bind_text(1, identity.mesh_name);
    stmt.bind_text(2, identity.local_device_name);
    stmt.bind_text(3, identity.local_public_key);
    stmt.bind_text(4, identity.local_private_key);
    stmt.bind_text(5, identity.local_fingerprint);
    stmt.bind_text(6, identity.mesh_secret);
    stmt.bind_int(7, identity.port);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw_sqlite_error(db_, "save_identity failed");
    }
}

std::optional<MeshIdentity> PersistenceStore::load_identity() {
    Stmt stmt(db_, R"(
        SELECT mesh_name, local_device_name, local_public_key, local_private_key,
               local_fingerprint, mesh_secret, port
        FROM mesh_identity WHERE id = 1;
    )");

    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_DONE) return std::nullopt;  // no saved identity yet -- first launch
    if (rc != SQLITE_ROW) throw_sqlite_error(db_, "load_identity failed");

    MeshIdentity identity;
    identity.mesh_name = stmt.column_text(0);
    identity.local_device_name = stmt.column_text(1);
    identity.local_public_key = stmt.column_text(2);
    identity.local_private_key = stmt.column_text(3);
    identity.local_fingerprint = stmt.column_text(4);
    identity.mesh_secret = stmt.column_text(5);
    identity.port = stmt.column_int(6);
    return identity;
}

void PersistenceStore::clear_identity() {
    exec_or_throw(db_, "DELETE FROM mesh_identity WHERE id = 1;");
}

void PersistenceStore::upsert_device(const TrustedDevice& device) {
    Stmt stmt(db_, R"(
        INSERT INTO trusted_devices (public_key, name, platform, ip_address, port, is_self)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(public_key) DO UPDATE SET
            name = excluded.name,
            platform = excluded.platform,
            ip_address = excluded.ip_address,
            port = excluded.port,
            is_self = excluded.is_self;
    )");
    stmt.bind_text(1, device.public_key);
    stmt.bind_text(2, device.name);
    stmt.bind_text(3, platform_to_string(device.platform));
    if (device.ip_address.has_value()) {
        stmt.bind_text(4, *device.ip_address);
    } else {
        stmt.bind_null(4);
    }
    stmt.bind_int(5, device.port);
    stmt.bind_int(6, device.is_self ? 1 : 0);

    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw_sqlite_error(db_, "upsert_device failed");
    }
}

void PersistenceStore::remove_device(const std::string& public_key) {
    Stmt stmt(db_, "DELETE FROM trusted_devices WHERE public_key = ?;");
    stmt.bind_text(1, public_key);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE) {
        throw_sqlite_error(db_, "remove_device failed");
    }
}

std::vector<TrustedDevice> PersistenceStore::load_all_devices() {
    Stmt stmt(db_, "SELECT public_key, name, platform, ip_address, port, is_self FROM trusted_devices;");

    std::vector<TrustedDevice> result;
    int rc;
    while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
        TrustedDevice device;
        device.public_key = stmt.column_text(0);
        device.name = stmt.column_text(1);
        device.platform = platform_from_string(stmt.column_text(2));
        device.connection_state = state_from_string("");  // always Offline on load -- see comment above
        device.active_rail = TransportRail::Lan;
        if (!stmt.column_is_null(3)) {
            device.ip_address = stmt.column_text(3);
        }
        device.port = stmt.column_int(4);
        device.latency_ms = 0;  // unknown until re-measured this session
        device.is_self = stmt.column_int(5) != 0;
        result.push_back(std::move(device));
    }
    if (rc != SQLITE_DONE) throw_sqlite_error(db_, "load_all_devices failed");
    return result;
}

void PersistenceStore::clear_all_devices() { exec_or_throw(db_, "DELETE FROM trusted_devices;"); }

std::string PersistenceStore::default_db_path() {
#ifdef _WIN32
    PWSTR path_wide = nullptr;
    std::string result;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path_wide))) {
        int len = WideCharToMultiByte(CP_UTF8, 0, path_wide, -1, nullptr, 0, nullptr, nullptr);
        std::string appdata(static_cast<size_t>(len) - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, path_wide, -1, appdata.data(), len, nullptr, nullptr);
        CoTaskMemFree(path_wide);
        std::string dir = appdata + "\\Rin";
        CreateDirectoryA(dir.c_str(), nullptr);  // ignore failure -- SQLite's own open error is the real signal
        result = dir + "\\mesh.db";
    } else {
        result = "rin_mesh.db";  // last-resort fallback: current working directory
    }
    return result;
#else
    const char* home = std::getenv("HOME");
    std::string dir = (home ? std::string(home) : ".") + "/.rin";
    mkdir(dir.c_str(), 0700);  // ignore failure -- SQLite's own open error is the real signal
    return dir + "/mesh.db";
#endif
}

}  // namespace rin
