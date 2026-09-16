rule Trojan_Win32_SmokeLoader_E_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c7 33 c1 8b ca c1 e9 ?? 03 4d f0 89 45 08 33 c8 89 4d 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 fc 8b 45 fc c1 e0 ?? 89 45 08 } 		$a_03_1 = {6a 73 58 6a 6d 66 a3 ?? ?? ?? ?? 58 6a 67 66 a3 ?? ?? ?? ?? 58 6a 69 66 a3 ?? ?? ?? ?? 58 6a 6c 66 a3 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}