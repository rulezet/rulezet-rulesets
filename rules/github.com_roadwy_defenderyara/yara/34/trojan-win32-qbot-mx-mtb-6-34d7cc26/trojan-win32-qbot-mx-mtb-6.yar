rule Trojan_Win32_Qbot_MX_MTB_6{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 08 88 0a 8b 55 ?? 83 c2 01 89 55 ?? eb } 		$a_02_1 = {83 c0 04 89 45 ?? e8 ?? ?? ?? ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? ?? ?? ba 18 30 00 00 85 d2 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}