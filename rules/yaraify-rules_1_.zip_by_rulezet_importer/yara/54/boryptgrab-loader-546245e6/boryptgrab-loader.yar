rule BoryptGrab_Loader
{
	meta:
		author = "Still"
		component_name = "BoryptGrab"
		component_name = "BlakcSeeStealer"
		date = "2026-05-22"
		description = "attempts to match strings/instructions found in BoryptGrab/BlakcSeeStealer loader"
		yarahub_uuid = "62a32bd9-9883-45cb-8c43-17069ece5b8d"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_reference_md5 = "d7f684659575575e90084fe49d9f259c"
	strings:
	
		$inst_decrypt_strings = {
			C6 45 ?? ??
			0F B6 ?? ??
			0F B6 ??
			66 0F 6E ??
			66 0F 60 ??
			[0-8]
			F3 0F 7E 0D ?? ?? ?? ??
			[0-8]
			66 0F EF 0D ?? ?? 01 00
			66 0F D6 0D ?? ?? 02 00
		}
	
		$inst_call_shellcode = {
			BA 20 00 00 00
			E8 [4]
			48 [2]
			40 [2] 01
			75 ??
			31 F6
			48 89 F9
			BA 01 00 00 00
			45 31 C0
			FF D3
		}
	
		$inst_cafebabedeadfood = {
			74 ??
			48 8B 05 ?? ?? ?? ??
			49 BE 0D F0 AD DE BE BA FE CA
			49 31 C6
			B9 20 00 00 00
			E8 ?? ?? ?? ??
			48 89 C3
		}
	
		$inst_VirtualAlloc_0xDAA00 = {
			3B 81 ?? ?? ?? ??
			0F 8F ?? ?? ?? ??
			48 8B 05 ?? ?? ?? ??
			48 85 C0
			0F 84 ?? ?? ?? ??
			BA 00 AA 0D 00
			31 C9
		}
	condition:
		2 of them
}