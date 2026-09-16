rule Trojan_Win32_Dridex_DM_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_00_0 = {b9 f0 02 00 00 31 d2 f7 f1 89 85 0c fd ff ff 31 ff 3b bd 0c fd ff ff 73 3c 69 c7 f0 02 00 00 ff 75 2c 8d 94 06 70 02 } 		$a_80_1 = {48 65 68 2a 2e 62 69 68 69 6c 65 } 		$a_80_2 = {68 49 5a 45 5f 68 54 48 4f 52 68 4f 5f 41 55 68 4c 45 5f 54 68 55 4e 41 42 68 45 } 		$a_80_3 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } 		$a_80_4 = {57 53 41 53 6f 63 6b 65 74 41 } 	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=20
 
}