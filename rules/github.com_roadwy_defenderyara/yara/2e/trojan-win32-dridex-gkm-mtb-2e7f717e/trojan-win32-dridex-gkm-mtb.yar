rule Trojan_Win32_Dridex_GKM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 14 18 88 13 8d 14 b1 03 d6 4f 8d 54 3a ?? 66 89 15 ?? ?? ?? ?? 0f b7 d2 8d 14 92 c1 e2 04 2b d1 43 03 f2 85 ff 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}