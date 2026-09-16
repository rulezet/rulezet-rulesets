rule Stealer_Stealc
{
	meta:
		author = "Still"
		component_name = "N/A"
		date = "2024-10-04"
		description = "attempts to match instructions/strings found in Stealc"
		malpedia_family = "win.stealc"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "2E84B07EA9D624E7D3DBE3F95C6DD8BA"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "858820c6-ce4e-41c8-9a5b-9098dd2a4746"
	strings:
		$str_1 = "-nop -c \"iex(New-Object Net.WebClient).DownloadString('" ascii
		$str_2 = "SELECT service, encrypted_token FROM token_service" ascii
		$str_3 = "browser: FileZilla\n" ascii
		$str_4 = "ChromeFuckNewCookies" ascii
		$str_5 = "/c timeout /t 10 & del /f /q \"" ascii
	
		$inst_low_match_peb = {
			55
			8B EC
			51
			C7 45 ?? 00 00 00 00
			64 A1 ?? ?? ?? ??
			8B 40 ??
			8B 40 ??
			8B 00
			8B 00
			8B 40 ??
			89 45 ??
			8B 45 ??
			8B E5
			5D
			C3
		}
	
		$inst_low_match_str_decode = {
			03 4D ??
			0F BE 19
			8B 55 ??
			52
			FF 15 ?? ?? ?? ??
			83 C4 04
			8B C8
			8B 45 ??
			33 D2
		}
	condition:
		3 of ($str_*) or all of ($inst_low_match_*)
}