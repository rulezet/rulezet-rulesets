rule DarkTortilla_2ndStage
{
	meta:
		author = "Still"
		component_name = "N/A"
		date = "2025-01-11"
		malpedia_family = "win.darktortilla"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "A102CEE15D494DB5AE6C917374FFBFC3"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "c5f0eefa-461d-499e-8f7b-71c01091c9b7"
		description = "Matches DarkTortilla second stage loader strings/bytecode"
	strings:
		$str_1 = "_GlobalOptions" ascii
		$str_2 = "_AntiVMs" ascii
		$str_3 = "_Melt" ascii
		$str_4 = "_PreStart" ascii
		$str_5 = "has been detected on ur computer" wide
		$str_6 = "for malicious ending," wide
		$str_7 = "ping 1.1.1.1 -n 1 -w 3000 > Nul & Del" wide
		$str_8 = "F.{0}.R" wide





















		$inst_addon_package = {
			28 [4]
			6F [4]
			00
			11 ??
			03
			72 [4]
			09
			8C [4]
			28 [4]
			6F [4]
			28 [4]
			6F [4]
			00
			04
			13 ??
			11 ??
			2C ??
			11 ??
			11 ??
			6F [4]
			28
		}














		$inst_exe_comp = {
			7E [4]
			6F [4]
			03
			72 [4]
			28 [4]
			28 [4]
			0A
			00
			28 [4]
			6F [4]
			02
			06
		}
	condition:
		3 of ($str_*) or
		any of ($inst_*)
}