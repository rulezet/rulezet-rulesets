rule Trojan_Win32_Trickbot_GKM_MTB_12{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 0c 02 f6 d1 3b c6 73 ?? 8a d0 2a 55 ?? 32 10 32 d1 88 10 03 c7 3b c6 72 ?? 8b 45 ?? 40 ff 4d ?? 89 45 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}