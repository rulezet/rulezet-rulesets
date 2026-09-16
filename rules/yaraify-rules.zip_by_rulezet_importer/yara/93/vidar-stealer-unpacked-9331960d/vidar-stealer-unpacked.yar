rule vidar_stealer_unpacked {
    meta:
        description = "Detects the unpacked Vidar binary."        
        author = "@jstrosch"
        date = "2023-01-07"
        yarahub_uuid = "b576e8fb-f45b-4da8-9cd9-a082ed88b34f"
        yarahub_license = "CC0 1.0"
        yrarahub_author_twitter = "@jstrosch"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "7b419724d28a464fa3ccead029201e05"

    strings:
        

        $c1 = {
            83 E4 F8
            E8 [4]
            E8 [4]
            E8 [4]
            E8 [4]
            E8 [4]
            E8 [4]
            E8 [4]
            E8 [4]
            E8 [4]
            E8 [4]
            33
        }

    condition:
        uint16(0) == 0x5a4d and $c1
}