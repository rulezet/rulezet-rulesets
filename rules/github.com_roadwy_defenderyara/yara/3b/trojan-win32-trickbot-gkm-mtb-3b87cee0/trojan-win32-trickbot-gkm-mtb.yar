rule Trojan_Win32_Trickbot_GKM_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 0c 8b 4d ?? 8b 55 ?? 03 c1 8a 14 32 30 10 41 3b 4d ?? 89 4d ?? 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}