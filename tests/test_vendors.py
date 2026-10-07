#!/usr/bin/env python3
"""Vendor attribution tests (BSSID -> OUI owner, virtual BSSIDs included).

Standalone: no Wi-Fi adapter and no IEEE registry file required -- the tests
run against a small in-memory registry shaped like the real one.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import wifi_scanner as scanner  # noqa: E402

REGISTRY = {
    "EC74D7": "Grandstream Networks Inc",
    "000B82": "Grandstream Networks Inc",
    "5CA4F4": "zte corporation",
    "301577": "Zyxel Communications Corporation",
    "98DED0": "TP-LINK TECHNOLOGIES CO.,LTD.",
    "ECDA3B": "Espressif Inc.",
}

GRANDSTREAM = "Grandstream Networks Inc"
VIRTUAL = scanner.VIRTUAL_BSSID_SUFFIX


def records(*bssids):
    return [{"bssid": bssid} for bssid in bssids]


def vendors(*bssids):
    annotated = scanner.annotate_vendors(records(*bssids), REGISTRY)
    return [rec["vendor"] for rec in annotated]


class RegistryLookupTests(unittest.TestCase):
    def test_global_address_resolves_to_owner(self):
        self.assertEqual(
            scanner.lookup_vendor("ec:74:d7:0b:7b:17", REGISTRY), GRANDSTREAM
        )
        self.assertEqual(
            scanner.lookup_vendor("EC:DA:3B:EB:DD:1B", REGISTRY), "Espressif Inc."
        )

    def test_unassigned_and_malformed_addresses(self):
        self.assertEqual(scanner.lookup_vendor("ac:bb:cc:dd:ee:ff", REGISTRY), "")
        self.assertEqual(scanner.lookup_vendor("not-a-mac", REGISTRY), "")
        self.assertEqual(scanner.lookup_vendor("", REGISTRY), "")

    def test_locally_administered_address_is_randomized_by_default(self):
        self.assertEqual(
            scanner.lookup_vendor("ee:74:d7:1b:7b:17", REGISTRY), scanner.RANDOMIZED_MAC
        )


class VirtualBssidTests(unittest.TestCase):
    def test_derived_bssid_takes_the_vendor_of_its_base_in_the_same_scan(self):
        # Real pair: the "Pavansutjio" AP serves two SSIDs, the second BSSID
        # differs from the base only in the administered bit and two index bits.
        self.assertEqual(
            vendors("ec:74:d7:0b:7b:17", "ee:74:d7:1b:7b:17", "ee:74:d7:1b:7b:16"),
            [GRANDSTREAM, GRANDSTREAM + VIRTUAL, GRANDSTREAM + VIRTUAL],
        )

    def test_administered_bit_alone_is_enough(self):
        self.assertEqual(
            vendors("00:0b:82:fa:a0:81", "02:0b:82:fa:a0:81"),
            [GRANDSTREAM, GRANDSTREAM + VIRTUAL],
        )

    def test_index_bits_in_the_first_octet_are_cleared_before_the_registry_lookup(self):
        # Base out of range: only the registry fallback can name this one.
        self.assertEqual(vendors("ee:74:d7:0b:7b:17"), [GRANDSTREAM + VIRTUAL])

    def test_nearest_base_wins_when_several_bases_are_in_range(self):
        self.assertEqual(
            vendors(
                "ec:74:d7:0b:7b:17",
                "5c:a4:f4:24:ab:17",
                "5e:a4:f4:24:ab:15",
            ),
            [GRANDSTREAM, "zte corporation", "zte corporation" + VIRTUAL],
        )

    def test_randomized_address_without_a_base_stays_randomized(self):
        self.assertEqual(
            vendors("ec:74:d7:0b:7b:17", "be:c5:63:e8:af:60"),
            [GRANDSTREAM, scanner.RANDOMIZED_MAC],
        )

    def test_shared_oui_tail_is_not_enough_when_the_distance_is_large(self):
        # Same middle OUI bytes as the TP-Link base, but 20 bits away: two
        # unrelated addresses must not be merged into one vendor.
        self.assertEqual(
            vendors("98:de:d0:e8:00:fb", "aa:de:d0:ff:ff:ff"),
            ["TP-LINK TECHNOLOGIES CO.,LTD.", scanner.RANDOMIZED_MAC],
        )

    def test_derived_bssid_is_not_invented_across_unrelated_ouis(self):
        self.assertEqual(
            vendors("ec:da:3b:eb:dd:1b", "7a:78:c9:82:73:7d"),
            ["Espressif Inc.", scanner.RANDOMIZED_MAC],
        )

    def test_annotation_is_idempotent_and_cached_per_address(self):
        annotated = scanner.annotate_vendors(
            records("ee:74:d7:1b:7b:17", "ee:74:d7:1b:7b:17", "ec:74:d7:0b:7b:17"),
            REGISTRY,
        )
        scanner.annotate_vendors(annotated, REGISTRY)
        self.assertEqual(
            [rec["vendor"] for rec in annotated],
            [GRANDSTREAM + VIRTUAL, GRANDSTREAM + VIRTUAL, GRANDSTREAM],
        )


class MacHelperTests(unittest.TestCase):
    def test_mac_round_trip_and_local_bit(self):
        value = scanner._mac48("ee:74:d7:1b:7b:16")
        self.assertEqual(scanner._mac_text(value), "ee:74:d7:1b:7b:16")
        self.assertTrue(scanner._is_locally_administered(value))
        self.assertFalse(scanner._is_locally_administered(scanner._mac48("ec:74:d7:0b:7b:17")))
        self.assertIsNone(scanner._mac48("12:34"))


if __name__ == "__main__":
    unittest.main()
