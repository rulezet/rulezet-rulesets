rule Trojan_Win32_Trickbot_GKM_MTB_7{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 08 8b 55 ?? 8b 02 8b 55 ?? 0f b6 04 02 8b 55 ?? 0f b6 0c 0a 33 c8 8b 55 ?? 8b 02 8b 55 ?? 88 0c 02 e9 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}