rule Heuristics_ChromeCookieMonster {
	meta:
		author = "Still"
		component_name = "N/A"
		date = "2024-10-04"
		description = "attempts to match strings related to Chromium's CookieMonster; typically used in Chromium secrets scanning by stealers; heuristics rule - may match false positives"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "2EC23E83E2F63AB27C25741B1F4D7F49"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "06a64dd1-d590-442a-997f-000293fabc65"
	strings:
		$str_1 = "network.mojom.NetworkService" ascii wide 
		$str_2 = "chrome.dll" ascii wide
		$str_byte_pattern_1 = {56574883EC384889CE488B05AA}
		$str_byte_pattern_1_1 = "56574883EC384889CE488B05AA"
		$str_byte_pattern_1_2 = {
			C6 [2-6] 56
			C6 [2-6] 57
			C6 [2-6] 48
			C6 [2-6] 83
			C6 [2-6] EC
			C6 [2-6] 28
			C6 [2-6] 89
			C6 [2-6] D7
			C6 [2-6] 48
		}
		$str_byte_pattern_2 = {01 00 00 4C 8D 44 24 28 49 89 10 48}
		$str_byte_pattern_2_1 = "0100004C8D44242849891048"
		$str_byte_pattern_2_2 = {
			C6 [2-6] 01
			C6 [2-6] 00
			C6 [2-6] 00
			C6 [2-6] 4c
			C6 [2-6] 8d
			C6 [2-6] 44
			C6 [2-6] 24
			C6 [2-6] 28
			C6 [2-6] 49
			C6 [2-6] 89
		}
	
		$inst_K32EnumProcessModulesEx = {
			33 DB
			48 8B F0
			48 85 C0
			0F 84 ?? ?? ?? ??
			4C 8D 4C 24 ??
			C7 44 24 ?? 03 00 00 00
			44 8B C7
			48 8B D0
			48 8B CD
		}
	
		$inst_scan_memory = {
			33 C9
			85 DB
			75 ??
			3D 2B 01 00 00
			75 ??
			4C 8B 44 24 ??
			4D 8B CE
			4C 2B C5
			4C 2B CE
			48 85 ED
		}
	condition:
		4 of ($str_*) or all of ($inst_*)
}