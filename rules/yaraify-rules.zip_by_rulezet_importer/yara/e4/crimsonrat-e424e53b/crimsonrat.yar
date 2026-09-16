rule CrimsonRAT
{
	meta:
		author = "Still"
		description = "Matches CrimsonRAT"
		date = "2024-04-20"
		malpedia_family = "win.crimson"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "22ce9042f6f78202c6c346cef1b6e532"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "22ddb8dc-69d6-4613-abde-b5ee241593bd"
	strings:























		$inst_process_command_code = {
			1B
			8D [4]
			0A
			02
			02
			7B [4]
			06
			16
			1B
			6F [4]
			7D [4]
			06
			16
			28 [4]
			0B
			07
			8D [4]
			0C
			16
			0D
			07
			13 ??
			2B
		}






















		$inst_get_file_info = {
			17
			8D [4]
			13 ??
			11 ??
			16
			1F 7C
			9D
			11 ??
			6F [4]
			16
			9A
			28 [4]
			0C
			08
			02
			07
			6F [4]
			28 [4]
			72 [4]
			28 [4]
			0C
		}



















		$inst_process_data = {
			02
			02
			7B [4]
			07
			16
			1B
			6F [4]
			7D [4]
			07
			16
			28 [4]
			0C
			08
			8D [4]
			0D
			08
			13 ??
			2B 
		}
	condition:
		any of them
}