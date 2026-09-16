rule Trojan_Win32_Dridex_AK_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b ca 83 c0 21 03 c8 53 55 56 8b 35 ?? ?? ?? ?? 2b d1 69 c1 04 67 01 00 83 c6 21 03 f2 } 		$a_02_1 = {3b c8 74 15 28 8a ?? ?? ?? ?? 8d 04 4d 04 00 00 00 41 a3 ?? ?? ?? ?? 03 c8 4a 83 fa 01 7f da } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}