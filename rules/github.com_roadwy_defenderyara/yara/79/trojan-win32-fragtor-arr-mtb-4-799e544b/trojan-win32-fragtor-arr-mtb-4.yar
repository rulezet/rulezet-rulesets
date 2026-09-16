rule Trojan_Win32_Fragtor_ARR_MTB_4{
	meta:
		description = "Trojan:Win32/Fragtor.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c2 03 c8 0f b6 c1 8a 84 05 fc fe ff ff 30 04 3e 46 8b 85 f4 fe ff ff 3b f3 } 		$a_03_1 = {0f b6 ca 03 c8 0f b6 c9 89 8d ?? ?? ?? ?? 8a 04 0e 88 03 43 83 ad ?? ?? ?? ?? ?? 88 14 0e 75 } 	condition:
		((#a_01_0  & 1)*12+(#a_03_1  & 1)*8) >=20
 
}