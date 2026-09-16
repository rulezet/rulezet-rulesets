rule Trojan_Win32_Dridex_AK_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {83 c1 f8 89 74 24 14 03 ca 8d 04 4d 06 00 00 00 89 44 24 18 8b 7c 24 1c 8d 50 46 03 d1 8b f2 } 		$a_02_1 = {8b 07 05 cc 10 06 01 89 07 83 c7 04 89 7c 24 1c 33 ff 2b d3 a3 ?? ?? ?? ?? 1b ff 2b 54 24 18 1b 7c 24 14 } 	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}