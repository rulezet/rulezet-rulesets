rule Trojan_Win32_Trickbot_GKM_MTB_3{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 33 c9 f7 35 ?? ?? ?? ?? 33 c0 8b 44 24 ?? 8a 0c 38 8a 14 32 32 ca 88 0c 38 8b 4c 24 ?? 40 3b c1 89 44 24 ?? 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}