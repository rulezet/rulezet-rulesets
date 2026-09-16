rule DarkTortilla_1stStage
{
	meta:
		author = "Still"
		component_name = "N/A"
		date = "2025-01-11"
		malpedia_family = "win.darktortilla"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "CE23E784C492814093F9056ABD00080F"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "4e908ca9-155e-4d51-8c45-07987a90b2ac"
		description = "Matches DarkTortilla first stage loader strings/bytecode"
	strings:
		$str_guid = "8a7cfae3-df2a-4003-acbd-c3480d51e4ee" ascii fullword
		$str_key = "Cc7x2YJs4w0S5XoZy9m8K" ascii fullword
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		$inst_load = {
			06
			17
			DA
			72 [4]
			28 [4]
			28 [4]
			A2
			1A
			13 ??
			38 [4]
			07
			74 [4]
			06
			28 [4]
			DE
		}

		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		$inst_reflection = {
			8D [4]
			A2
			14
			14
			14
			17
			28 [4]
			26
			7E [4]
			20 [4]
			7E [4]
			20 [4]
			93
			7E [4]
			20
		}
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		$inst_aes_setup = {
			13 ??
			11 ??
			74 [4]
			14
			FE ??
			13 ??
			11 ??
			2C ??
			17
			13 ??
			2B ??
			19
			2B ??
			11 ??
			74 [4]
			08
			74 [4]
			6F [4]
			11 ??
			74
		}
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		$inst_str_ref = {
			06
			74 [4]
			7E [4]
			20 [4]
			7E [4]
			20 [4]
			93
			7E [4]
			20 [4]
			93
			61
			20 [4]
			5F
			9D
		}
	condition:
		any of ($str_*) or
		2 of ($inst_*)
}