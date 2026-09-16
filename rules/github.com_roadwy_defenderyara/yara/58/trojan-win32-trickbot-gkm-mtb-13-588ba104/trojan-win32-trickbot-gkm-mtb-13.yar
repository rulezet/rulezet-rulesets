rule Trojan_Win32_Trickbot_GKM_MTB_13{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 04 0a f6 d0 88 45 ?? 8b d9 3b 4d ?? 73 ?? eb ?? 8a 45 ?? 8a cb 2a 4d ?? be 23 00 00 00 32 0b 32 c8 88 0b 6a 14 68 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}