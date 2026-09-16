rule Trojan_Win32_Raccrypt_GB_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {b8 3b 2d 0b 00 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d } 		$a_02_1 = {c1 e0 04 89 01 c3 83 3d ?? ?? ?? ?? 7e 90 18 8b 44 24 04 31 06 c2 04 00 33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3 29 08 c3 } 	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}