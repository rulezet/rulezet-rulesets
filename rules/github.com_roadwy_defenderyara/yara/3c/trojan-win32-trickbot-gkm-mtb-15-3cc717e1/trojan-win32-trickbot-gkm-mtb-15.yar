rule Trojan_Win32_Trickbot_GKM_MTB_15{
	meta:
		description = "Trojan:Win32/Trickbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 14 02 00 00 f7 f9 8a 5d 00 8b 44 24 ?? 83 c0 f0 c7 84 24 ?? ?? ?? ?? ff ff ff ff 8d 48 ?? 8a 54 14 18 32 da 88 5d 00 45 83 ca ff f0 0f c1 11 4a 85 d2 7f } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}