// Persistence tests.
//
// The single most important thing to prove here: an identity + trusted
// device list saved by one PersistenceStore instance is loaded correctly
// by a SEPARATE instance pointed at the same file -- simulating an
// actual app restart, not just "the object works while it's alive."

#include "rin/persistence.hpp"
#include "rin/mesh_engine.hpp"

#include <cstdio>
#include <filesystem>
#include <iostream>

using namespace rin;

namespace {
int g_failures = 0;

void check(bool condition, const std::string& name) {
    if (condition) {
        std::cout << "  [PASS] " << name << "\n";
    } else {
        std::cout << "  [FAIL] " << name << "\n";
        g_failures++;
    }
}

std::string temp_db_path(const std::string& suffix) {
    auto dir = std::filesystem::temp_directory_path();
    return (dir / ("rin_test_" + suffix + ".db")).string();
}
}  // namespace

void run_persistence_tests() {
    std::cout << "\n== Persistence tests ==\n";

    // -- Fresh database: no identity yet ---------------------------------
    {
        std::string path = temp_db_path("fresh");
        std::filesystem::remove(path);

        PersistenceStore store(path);
        auto identity = store.load_identity();
        check(!identity.has_value(), "a freshly created database has no saved identity");
        check(store.load_all_devices().empty(), "a freshly created database has no saved devices");

        std::filesystem::remove(path);
    }

    // -- Save then load identity, SAME instance --------------------------
    {
        std::string path = temp_db_path("same_instance");
        std::filesystem::remove(path);

        PersistenceStore store(path);
        MeshIdentity identity;
        identity.mesh_name = "Test Mesh";
        identity.local_device_name = "Test PC";
        identity.local_public_key = "fake_pub_key_base64";
        identity.local_private_key = "fake_priv_key_base64";
        identity.local_fingerprint = "key:abcd...wxyz";
        identity.mesh_secret = "fake_mesh_secret_hex";
        identity.port = 45990;

        store.save_identity(identity);
        auto loaded = store.load_identity();
        check(loaded.has_value(), "identity round-trips within the same store instance");
        if (loaded.has_value()) {
            check(loaded->mesh_name == identity.mesh_name, "mesh_name preserved");
            check(loaded->local_private_key == identity.local_private_key,
                  "local_private_key preserved (this is the most safety-critical field to get right)");
            check(loaded->mesh_secret == identity.mesh_secret, "mesh_secret preserved");
            check(loaded->port == identity.port, "port preserved");
        }

        std::filesystem::remove(path);
    }

    // -- Save then load, SEPARATE instance -- simulates an actual restart --
    {
        std::string path = temp_db_path("restart_sim");
        std::filesystem::remove(path);

        MeshIdentity identity;
        identity.mesh_name = "Restart Test Mesh";
        identity.local_device_name = "Restart PC";
        identity.local_public_key = "restart_pub_key";
        identity.local_private_key = "restart_priv_key";
        identity.local_fingerprint = "key:1111...2222";
        identity.mesh_secret = "restart_secret";
        identity.port = 45991;

        TrustedDevice peer;
        peer.public_key = "peer_pub_key";
        peer.name = "Some Phone";
        peer.platform = PlatformType::Android;
        peer.ip_address = "192.168.1.50";
        peer.port = 45990;
        peer.is_self = false;

        {
            PersistenceStore writer(path);
            writer.save_identity(identity);
            writer.upsert_device(peer);
        }  // writer destructs here -- closes the DB, simulating process exit

        {
            PersistenceStore reader(path);  // a genuinely separate instance/open
            auto loaded_identity = reader.load_identity();
            check(loaded_identity.has_value(), "identity survives across separate store instances (simulated restart)");
            if (loaded_identity.has_value()) {
                check(loaded_identity->mesh_name == "Restart Test Mesh", "mesh_name survives restart");
                check(loaded_identity->local_private_key == "restart_priv_key", "private key survives restart");
            }

            auto devices = reader.load_all_devices();
            check(devices.size() == 1, "trusted device list survives restart");
            if (!devices.empty()) {
                check(devices[0].public_key == "peer_pub_key", "device public_key survives restart");
                check(devices[0].name == "Some Phone", "device name survives restart");
                check(devices[0].platform == PlatformType::Android, "device platform survives restart");
                check(devices[0].ip_address.has_value() && *devices[0].ip_address == "192.168.1.50",
                      "device IP address survives restart");
                check(devices[0].connection_state == ConnectionState::Offline,
                      "a loaded device's connection_state is always Offline, never a stale CONNECTED from last session");
            }
        }

        std::filesystem::remove(path);
    }

    // -- Upsert overwrites, doesn't duplicate ----------------------------
    {
        std::string path = temp_db_path("upsert");
        std::filesystem::remove(path);
        PersistenceStore store(path);

        TrustedDevice device;
        device.public_key = "same_key";
        device.name = "Original Name";
        device.port = 1000;
        store.upsert_device(device);

        device.name = "Updated Name";
        device.port = 2000;
        store.upsert_device(device);

        auto devices = store.load_all_devices();
        check(devices.size() == 1, "upserting the same public_key twice results in ONE row, not two");
        if (!devices.empty()) {
            check(devices[0].name == "Updated Name", "the second upsert's values win");
            check(devices[0].port == 2000, "the second upsert's port wins");
        }

        std::filesystem::remove(path);
    }

    // -- remove_device actually removes -----------------------------
    {
        std::string path = temp_db_path("remove");
        std::filesystem::remove(path);
        PersistenceStore store(path);

        TrustedDevice a, b;
        a.public_key = "key_a";
        a.name = "Device A";
        b.public_key = "key_b";
        b.name = "Device B";
        store.upsert_device(a);
        store.upsert_device(b);
        check(store.load_all_devices().size() == 2, "two devices saved");

        store.remove_device("key_a");
        auto remaining = store.load_all_devices();
        check(remaining.size() == 1, "removing one device leaves exactly one");
        if (!remaining.empty()) {
            check(remaining[0].public_key == "key_b", "the REMAINING device is the one that wasn't removed");
        }

        std::filesystem::remove(path);
    }

    // -- clear_identity / clear_all_devices -------------------------
    {
        std::string path = temp_db_path("clear");
        std::filesystem::remove(path);
        PersistenceStore store(path);

        MeshIdentity identity;
        identity.mesh_name = "To Be Cleared";
        store.save_identity(identity);
        TrustedDevice device;
        device.public_key = "will_be_cleared";
        store.upsert_device(device);

        store.clear_identity();
        check(!store.load_identity().has_value(), "clear_identity() actually removes the saved identity");

        store.clear_all_devices();
        check(store.load_all_devices().empty(), "clear_all_devices() actually removes all saved devices");

        std::filesystem::remove(path);
    }

    // -- A device with no IP address (never resolved) round-trips as nullopt --
    {
        std::string path = temp_db_path("no_ip");
        std::filesystem::remove(path);
        PersistenceStore store(path);

        TrustedDevice device;
        device.public_key = "no_ip_key";
        device.name = "Unresolved Device";
        device.ip_address = std::nullopt;
        store.upsert_device(device);

        auto devices = store.load_all_devices();
        check(devices.size() == 1 && !devices[0].ip_address.has_value(),
              "a device saved with no IP address loads back with ip_address as nullopt, not an empty string");

        std::filesystem::remove(path);
    }

    // -- End-to-end wiring: MeshEngine::try_load_persisted / create_initial_mesh --
    {
        std::string path = temp_db_path("engine_e2e");
        std::filesystem::remove(path);

        asio::io_context io1;
        std::string saved_fingerprint;
        std::string saved_mesh_name;
        {
            MeshEngine engine(io1);
            bool loaded = engine.try_load_persisted(path);
            check(!loaded, "a fresh MeshEngine against a nonexistent db has nothing to load");
            engine.create_initial_mesh("E2E Mesh", "E2E Device");
            saved_fingerprint = engine.identity().local_fingerprint;
            saved_mesh_name = engine.identity().mesh_name;
        }  // engine destructs -- but try_load_persisted was called with an explicit
           // path, and create_initial_mesh only opens its OWN store if store_ is
           // still null; since try_load_persisted already set store_, the save
           // happens through that same path-bound store.

        {
            asio::io_context io2;
            MeshEngine engine2(io2);
            bool loaded = engine2.try_load_persisted(path);
            check(loaded, "a second MeshEngine instance against the same db file loads the identity created by the first");
            if (loaded) {
                check(engine2.identity().mesh_name == saved_mesh_name,
                      "the reloaded mesh_name matches what create_initial_mesh set originally");
                check(engine2.identity().local_fingerprint == saved_fingerprint,
                      "the reloaded fingerprint matches -- proves the actual keypair survived, not just metadata");
                auto devices = engine2.trusted_devices();
                check(!devices.empty(), "the self-device entry created by create_initial_mesh survives reload");
            }
        }

        std::filesystem::remove(path);
    }

    std::cout << (g_failures == 0 ? "All persistence tests passed.\n" : "SOME PERSISTENCE TESTS FAILED.\n");
}

int g_persistence_test_failures() { return g_failures; }
