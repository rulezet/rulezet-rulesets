rule Kimsuky_related {
	meta:
		author = "Still"
		component_name = "N/A"
		date = "2024-05-25"
		description = "attempts to match httpSpy module potentially related to Kimsuky"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "27d4ff7439694041ef86233c2b804e1f"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "6e030925-4990-4bc3-91e6-74659fad0348"
	strings:
		$str_1 = "regsvr32.exe /s %s" wide fullword
		$str_2 = "sc delete CacheDB" wide fullword
		$str_3 = "%s%sc %s >%s 2>&1" wide fullword
		$str_4 = "ctx=" ascii fullword
	
		$inst_fnv = {
			48 63 D0
			48 33 55 ??
			49 0F AF D2
			44 8B 4D ??
			41 83 C1 01
		}
	
		$inst_xor = {
			EB ??
			8B 95 ?? ?? ?? ??
			33 95 ?? ?? ?? ??
			88 51 ??
			48 83 C1 08
			48 8B 95 ?? ?? ?? ??
			48 83 C2 14
		}
	
		$inst_screenshot = {
			C7 44 24 ?? 20 00 CC 00
			4C 89 E1
			31 D2
			45 31 C0
			41 89 D9
			FF 15 ?? ?? ?? ??
			0F 57 F6
			0F 29 B5 ?? ?? ?? ??
			0F 29 B5 ?? ?? ?? ??
			4C 8D 85 ?? ?? ?? ??
			4C 89 F9
			BA 20 00 00 00
		}
	
		$inst_a = {
			8B 44 24 ??
			89 44 24 ??
			8B 44 24 ??
			D1 F8
			89 44 24 ??
			83 7C 24 ?? 00
			B9 E4 6F DF F3
			0F 84 ?? ?? ?? ??
		}
	
	
	condition:
		2 of ($str_*) or 2 of ($inst_*)
}