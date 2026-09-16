rule Trojan_Win32_IcedID_AF_MTB{
	meta:
		description = "Trojan:Win32/IcedID.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {02 4c 24 07 2a c2 2a 44 24 08 02 c9 55 2a c1 0f b6 e9 56 2c 69 57 88 44 24 13 } 		$a_02_1 = {89 4d fc 8b 15 ?? ?? ?? ?? 81 c2 79 8f 0e 00 89 55 fc 6b 45 0c 4e 0f af 45 fc } 	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}