from cryptography.hazmat.primitives import serialization

from warrant.keystore import load_or_create_ec_key


def test_creates_a_key_file_that_did_not_exist(tmp_path):
    path = tmp_path / "signing" / "key.pem"
    key = load_or_create_ec_key(str(path))
    assert path.exists()
    assert path.stat().st_mode & 0o777 == 0o600
    # It's actually usable as an EC private key, not just bytes on disk.
    key.public_key()


def test_second_call_loads_the_same_key_instead_of_regenerating(tmp_path):
    path = tmp_path / "key.pem"
    first = load_or_create_ec_key(str(path))
    second = load_or_create_ec_key(str(path))

    first_pub = first.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    second_pub = second.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert first_pub == second_pub


def test_two_independent_paths_get_two_different_keys(tmp_path):
    key_a = load_or_create_ec_key(str(tmp_path / "a.pem"))
    key_b = load_or_create_ec_key(str(tmp_path / "b.pem"))

    pub_a = key_a.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_b = key_b.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert pub_a != pub_b


def test_concurrent_first_boot_race_all_processes_converge_on_one_key(tmp_path):
    # Simulates N replicas starting simultaneously against an empty shared path: only one
    # should win the O_EXCL create; everyone else must load that winner's key, not each mint
    # their own. Real concurrency (threads racing the same call), not simulated sequentially.
    import threading

    path = tmp_path / "race.pem"
    results = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        results.append(load_or_create_ec_key(str(path)))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    pubs = {
        k.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        for k in results
    }
    assert len(pubs) == 1, "every thread must converge on the same key, not each write its own"
