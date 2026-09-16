rule Trojan_Win32_Dridex_AA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 16 03 f8 0f b7 c1 03 d8 89 1d ?? ?? ?? ?? 0f b7 1d ?? ?? ?? ?? 2b eb 81 fd 6a 02 00 00 } 		$a_02_1 = {8d 4c 28 01 81 c2 cc bc 05 01 0f b7 c9 89 16 89 15 ?? ?? ?? ?? 0f b7 d1 8d 84 00 e8 3b 00 00 2b c2 03 c7 83 c6 04 83 6c 24 10 01 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}