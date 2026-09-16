rule SimpleTea {
	meta:
		author = "Still"
		component_name = "SimpleTea"
		date = "2024-05-25"
		description = "attempts to match strings/instructions found in SimpleTea"
		malpedia_family = "elf.simpletea"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "05957d98a75c04597649295dc846682d"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "05762902-c9e5-4d94-883f-ae552f53d2bc"
	strings:
		$key = {77 4C 71 66 4D 5D 25 77  54 78 60 7E 74 55 54 62
77 3E 52 5E 18 23 79 47  35 52 28 33 7F 43 3A 3B}
		$str_1 = "XEncoding" ascii
		$str_2 = "CryptPayload" ascii
		$str_3 = "RecvPayload" ascii
		$str_4 = "MsgCmd" ascii
		$str_5 = "AcceptRequest" ascii
		$str_6 = "FConnectProxy" ascii
	
		$inst_xor = {
			89 C6
			83 E6 1F
			8A 0C 3E
			30 0C 03
			48 FF C0
			48 39 C2
		}
	
		$inst_msgcmd = {
			74 ??
			48 8B 8D ?? ?? ?? ??
			44 8D 34 01
			41 81 FE FF 7E 01 00
			0F 87 ?? ?? ?? ??
			89 C9
		}
	
		$inst_command_handler = {
			E8 [4]
			48 B8 9A 08 00 00 (99|92|95) 08 00 00
			49 89 47 ??
			48 8D BD ?? ?? ?? ??
		}
	
	condition:
		$key or 
		4 of ($str_*) or 
		any of ($inst_*)
}