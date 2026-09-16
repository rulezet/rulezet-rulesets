rule Trojan_Win32_SmokeLoader_ARR_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_03_0 = {23 e9 30 d0 b1 ?? e5 ?? bd ?? ?? ?? ?? 18 63 ?? 96 85 17 b2 5b } 		$a_01_1 = {20 14 72 f3 1b 4d af 89 f0 84 28 2f fa 2d } 		$a_01_2 = {97 a5 2a 24 97 5d a1 } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*8+(#a_01_2  & 1)*2) >=20
 
}