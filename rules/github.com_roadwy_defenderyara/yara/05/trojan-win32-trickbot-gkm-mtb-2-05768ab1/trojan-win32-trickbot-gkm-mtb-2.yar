rule Trojan_Win32_Trickbot_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 18 f6 d0 88 45 ?? 3b d9 73 ?? eb ?? 8a 45 ?? 8a cb 2a 4d ?? 32 0b 32 c8 88 0b 03 df 85 f6 74 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}