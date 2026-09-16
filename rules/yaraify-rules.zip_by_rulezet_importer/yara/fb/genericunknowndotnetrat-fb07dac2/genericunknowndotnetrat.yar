rule GenericUnknownDotnetRAT {
	meta:
		author = "Still"
		component_name = "UnknownDotnetRAT"
		date = "2025-11-07"
		description = "attempts to match instructions found in .NET backdoors related to XWorm/VenomRAT"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "f40e0a193d43d43bad1aaf2657868aaa"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "bf8005e7-0b51-49ba-9522-ec9b2a09239f"
	strings:
		
		
		
		
		
		
		$inst_thread_sleep = {
			38 [4]
			28 [4]
			20 E8 03 00 00
			20 88 13 00 00
			28 [4]
			28
		}

		
		
		
		
		
		
		
		$inst_setup_socket = {
			7E [4]
			20 00 C8 00 00
			28 [4]
			7E [4]
			7E [4]
			7E [4]
			28
		}

		
		
		
		
		
		
		
		
		$inst_timer = {
			0A
			06
			14
			28 [4]
			20 10 27 00 00
			20 98 3A 00 00
			28 [4]
			28
		}
	condition:
		any of them
}