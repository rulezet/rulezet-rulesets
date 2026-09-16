rule Gh0st_Variant
{
	meta:
		author = "Still"
		component_name = "Gh0st"
		date = "2025-04-12"
		malpedia_family = "win.ghost_rat"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "d3be6473fd43aa87a5a58a861c5bdcbc"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "d0cfda87-1635-4b9b-96d2-aad99f668b2c"
		description = "Matches an unknown Gh0st variant that targets social media apps"
	strings:
		$str_1 = "cmd /c fsutil file layout" ascii
		$str_2 = "chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn/home.html" ascii fullword
		$str_3 = "--no-sandbox --allow-no-sandbox-job" ascii
		$str_4 = "OK.\x0d\x0aStarting TransmitData\x0d\x0a" ascii fullword
		$str_5 = "Creating a ctrlconnection...%s:%d\x0d\x0a" ascii fullword
		$str_6 = "ThreadID: %d ==> Connecting to Client...\x0d\x0a" ascii fullword
		$str_7 = "nsocket-di:%d" ascii fullword
		$str_8 = { B7 C0 BB F0 C7 BD 20 3A 20 20 B4 F2 BF AA 0D 0A 00 }
		$str_9 = { 52 75 6E C6 F4 B6 AF CF EE 3A 0D 0A 00 }
		$str_10 = "0000000000end....\r\n" ascii fullword
		$str_11 = "CFileManager::SendFileData" ascii
		$str_12 = "CFileManager::GetFileData" ascii
		$str_13 = "C Drive error" ascii fullword
		$class_name_1 = "CHiddenDeskTop" ascii
		$class_name_2 = "CMyProxyMap" ascii
		$class_name_3 = "CGetClip" ascii
		$class_name_4 = "CCursorInfo" ascii
	
		$inst_filesize = {
			8B C8
			B8 01 F8 3F 00
			F7 E1
			8B F2
			C1 EE 03
			FF D3
		}
	
		$inst_xor = {
			3B C8
			72 ??
			3B CB
			73 ??
			80 34 31 60
			41
			3B CB
			72 ??
			8D 7B ??
			57
		}
	
		$inst_xor_2 = {
			3B C2
			72 ??
			3B C6
			73 ??
			0F 1F 00
			80 34 38 60
			40
			3B C6
			72 ??
			85 F6
			0F 8E ?? ?? ?? ??
			68 18 08 00 00
		}
	condition:
		4 of ($str_*) or
		3 of ($class_name_*) or
		any of ($inst_*)
}