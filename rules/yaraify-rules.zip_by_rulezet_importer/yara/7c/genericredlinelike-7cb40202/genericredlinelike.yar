rule GenericRedLineLike
{
	meta:
		author = "Still"
		description = "Matches RedLine-like stealer; may match its variants."
		date = "2024-04-10"
		malpedia_family = "win.redline_stealer"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "09C25A0198EB2D54A9A38D333DF61C5C"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "268ae748-bb51-40a5-921d-3dc7a32b2205"
	strings:
		
		
		
		
		
		
		
		
		
		
		
		
		
		$instruction_file_search = {
			6F [4]
			0D
			[0-1]
			07
			20 00 00 20 03
			6A
			FE ??
			16
			FE ??
			13 ??
			11 ??
			2C ??
			38
		}




















		$instruction_create_patched_lnk = {
			7E [4]
			11 ??
			11 ??
			6F [4]
			6F [4]
			13 ??
			00
			07
			13 ??
			16
			13 ??
			2B ??
			11 ??
			11 ??
			9A
			13 ??
			00
			11 ??
			6F [4]
			11
		}


















		$instruction_read_c2_config = {
			7E [4]
			7E [4]
			28 [4]
			17
			8D [4]
			25
			16
			1F 7C
			9D
			6F [4]
			13 ??
			16
			13 ??
			2B ??
			11 ??
			11 ??
			9A
			13
		}


















		$instruction_get_browsers = {
			6F [4]
			6F [4]
			28 [4]
			6F [4]
			[0-1]
			11 ??
			6F [4]
			14
			FE ??
			13 ??
			11 ??
			2C ??
			11 ??
			11 ??
			6F [4]
			28 [4]
			6F [4]
			6F
		}
	condition:
		any of them
}