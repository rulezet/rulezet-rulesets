rule Trojan_Win32_Qbot_MX_MTB_10{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 04 06 88 04 0a 8b 4d ?? 83 c1 01 89 4d } 		$a_02_1 = {8b 55 ec 89 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? 3b 05 ?? ?? ?? ?? 72 ?? eb ?? b9 39 00 00 00 85 c9 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}