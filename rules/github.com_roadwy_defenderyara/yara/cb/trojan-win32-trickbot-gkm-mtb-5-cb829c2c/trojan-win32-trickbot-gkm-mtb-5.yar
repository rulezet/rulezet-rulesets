rule Trojan_Win32_Trickbot_GKM_MTB_5{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 8b 08 8b 55 ?? 8b 02 8b 55 ?? 8b 75 ?? 8a 0c 0a 32 0c 06 8b 55 ?? 8b 02 8b 55 ?? 88 0c 02 e9 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}