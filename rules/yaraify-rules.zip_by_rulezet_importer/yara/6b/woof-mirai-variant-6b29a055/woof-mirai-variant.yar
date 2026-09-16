rule woof_mirai_variant {
    meta:
        description = "Detects Woof Mirai variant (ChaCha20 table, HTTP C2 with token/guid, .woof dropper)"
        author = "Nokia Deepfield ERT"
        date = "2026-03-18"
        reference = "Internal analysis of sample 6ef4ce02"
        hash = "6ef4ce0234770f729b0102c51b7a981b65b4f24af65c9e9a1e19a5d2ce780f01"
        tlp = "WHITE"
        yarahub_uuid = "66d7dacb-73e8-4e9e-af67-04d53ef2c626"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "3cbd519495ec3f1fc7ba19f3cca8c2fe"

    strings:
                $chacha_key = { 5a 3f 2e 7b 8c 9d 0a 6e 3b 4f 7c 8a 1d 5c 2b 0d
                        6f 1a 0c 3e 2d 8e 4a 09 1c 7e 5a 4d 3c 2b 6a 08 }

                $chacha_nonce = { 4a 1b 00 ff 2d 7c 3a 12 00 01 03 05 }

                $c2_token = "token=" ascii
        $c2_guid = "&guid=" ascii
        $c2_getinfo = "getinfo" ascii
                $bot_seed = "14861879" ascii

                $shout = "SHOUT" ascii

                $scan_template = { 19 00 d4 02 12 33 31 2e 32 31 34 2e 32 34 34 2e 31 39 }

                $woof = ".woof" ascii

    condition:
        uint32(0) == 0x464c457f and          (
            $chacha_key or
            $chacha_nonce or
            ($c2_token and $c2_guid and $c2_getinfo) or
            ($bot_seed and $shout) or
            $scan_template or
            ($woof and $c2_token and $c2_guid)
        )
}