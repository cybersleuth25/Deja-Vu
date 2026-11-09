import seed_data


def test_counts_and_ids(incidents):
    assert len(incidents) == 32
    assert sum(i["type"] == "outage" for i in incidents) == 22
    assert sum(i["type"] == "security" for i in incidents) == 10
    assert [i["id"] for i in incidents] == [f"INC-{n:04d}" for n in range(1, 33)]
    assert all("2026-08-01" <= i["opened_at"] < "2026-12-01" for i in incidents)


def test_file_matches_generator(incidents):
    assert incidents == seed_data.build()


def test_planted_patterns(incidents):
    v = seed_data.verify(incidents)
    assert v["tuesday_evening"][:2] == (8, 10)
    assert v["auth_before_last6"][:2] == (4, 6)
    assert len(v["pool_incidents"]) == 4
    assert v["restart_pool"] == (0, 4)
    assert v["rollback_pool"] == (3, 4)
    assert len(v["asn_incidents"]) >= 3
    assert v["per_ip_rate_limit"][0] == 0 and v["per_ip_rate_limit"][1] >= 3
    assert v["block_asn"][0] / v["block_asn"][1] > 0.5


def test_action_strings_are_canonical(incidents):
    # Near-duplicates (case or whitespace) would split success rates.
    names = {a["action"] for i in incidents for a in i["actions"]}
    normalised = {n.lower().strip() for n in names}
    assert len(names) == len(normalised)
