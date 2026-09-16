rule BadIISModule
{
	meta:
		author = "Still"
		component_name = "BadIIS"
		date = "2025-09-20"
		description = "attempts to match the strings and instructions found in BadIIS"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "1ca50c2d1b82732fc6c834bbdd4e34e2"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "004c973e-8627-4740-ac2d-f97d1f1477a7"
	strings:
		$rtti_1 = "AVUploadServer" ascii
		$rtti_2 = "AVHiJackServer" ascii
		$rtti_3 = "AVRedirectServer" ascii
		$rtti_4 = "AVWebdllServer" ascii
		$rtti_5 = "AVAffLinkServer" ascii
		$rtti_6 = "AVBaseServer" ascii
		$pdb_set1_1 = "D:\\DriverSpace\\"
		$pdb_set1_2 = "\\hidden\\x64\\"
		$pdb_set1_3 = "\\Winkbj.pdb"
		$pdb_set2_1 = "\\Dongtai.pdb" ascii
		$pdb_set2_2 = "\\IIS\\IISCPP-GM\\" ascii
		$pdb_set2_3 = "D:\\IIS\\" ascii
		$str_1 = "Message: ok<br>\r\n" ascii fullword
		$str_2 = "Plugin Version: " ascii fullword
		$str_3 = "hj-plugin-iis-cpp-v" ascii
		$str_4 = "TryCleanTmp:" ascii
		$str_5 = "FAB234CD3-09434-8898D-BFFC-4E23123DF2C" ascii
		$str_6 = ",open failed" ascii fullword
		$str_7 = "DeleteFilesByPercentage" ascii
		$str_8 = "xxfailed: " ascii
		$str_9 = "PostReportNoRemoteConfig:existed!" ascii fullword
		$str_10 = "name='cmdml' placeholder='Enter CMD" ascii
	
		$inst_passwd_check = {
			0F 85 ?? ?? ?? ??
			48 B9 68 61 63 6B 31 32 33 34
			48 39 08
			0F 85 ?? ?? ?? ??
			66 81 78 ?? 35 36
			0F 85 ?? ?? ?? ??
			80 78 ?? 21
			0F 85
		}
	
		$inst_alloc_cmd = {
			41 B8 00 30 00 00
			FF 15 ?? ?? ?? ??
			48 8B F8
			48 83 7B ?? 10
			72 ??
			48 8B 1B
			4C 8B CB
			4C 8D 05 ?? ?? ?? ??
			BA 04 01 00 00
			48 8B CF
			E8 ?? ?? ?? ??
			4C 89 65 ??
			4C 89 65 ??
			4C 89 65 ??
			4C 89 65 ??
			48 C7 45 ?? 0F 00 00 00
			44 88 65 ??
			41 B8 24 00 00 00
		}
	condition:
		3 of ($rtti_*) or
		2 of ($pdb_set1_*) or
		2 of ($pdb_set2_*) or
		4 of ($str_*) or
		any of ($inst_*)
}