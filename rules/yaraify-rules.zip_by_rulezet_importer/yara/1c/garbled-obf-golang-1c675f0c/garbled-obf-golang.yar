rule garbled_obf_golang {
	meta:
        date = "2025-04-09"
		yarahub_reference_md5= "68b329da9893e34099c7d8ad5cb9c940"
        yarahub_uuid = "0c1c0fd8-6e61-4740-9626-bde9a82a13f0"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
                                                        $ = { 0f b6 ?? ?? ?? 0f b6 ?? ?? ?? 89 f7 31 d6 8d ?? ?? ?? 8d ?? ?? }
    condition:
        all of them
}