rule StealcV2 {
	meta:
		author = "Still"
		component_name = "Stealc"
		date = "2025-04-26"
		description = "attempts to match the instructions found in StealcV2"
		malpedia_family = "win.stealc"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "12247ebf4653796ec00abd7c8f59b149"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "9503350b-72f6-4ae3-b22f-3646caf8e2bd"
	strings:

	
	
		$inst_rc4 = {
			8A 04 ??
			[0-8]
			44 88 [2]
			[0-8]
			49 83 7D 18 0F
			[2-8]
			76 04
			49 8B 55 00
		}
	
		$inst_screenshot = {
			FF 15 ?? ?? ?? ??
			B9 4D 00 00 00
			48 89 44 24 ??
			FF 15 ?? ?? ?? ??
			B9 4C 00 00 00
			8B F8
			FF 15 ?? ?? ?? ??
			C7 44 24 ?? 20 00 CC 00
			45 8B CE
			89 7C 24 ??
			45 33 C0
			89 44 24 ??
			33 D2
			4C 89 ?? 24 ??
			49 8B ??
			89 74 24 ??
			FF 15 ?? ?? ?? ??
			[0-8]
			4C 8D 44 24 ??
			[0-4]
			33 D2
		}
	
	
		$inst_get_cpu_info = {
			C7 84 24 ?? ?? ?? ?? 00 02 00 00
			48 8D 15 ?? ?? ?? ??
			48 8D 8C 24 ?? ?? ?? ??
			E8 ?? ?? ?? ??
			[8-12]
			76 ??
			48 8B 00
			48 8D 8C 24 ?? ?? ?? ??
			48 89 4C 24 ??
			41 B9 19 01 02 00
			45 33 C0
			48 8B D0
			48 C7 C1 02 00 00 80
		}
	
		$inst_main = {
			48 83 C3 78
			48 3B DF
			75 ??
			80 7D ?? 00
			74 ??
			48 8D 4D ??
			E8
		}
	condition:
		any of them
}