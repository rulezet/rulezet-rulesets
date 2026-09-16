rule Trojan_Win32_Trickbot_GKM_MTB_14{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 0c 32 f6 d1 8b c6 3b f7 73 ?? eb ?? 8d 49 00 8a d0 2a d3 32 10 32 d1 88 10 03 45 ?? 3b c7 72 ?? 8b 55 ?? 46 ff 4d ?? 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}