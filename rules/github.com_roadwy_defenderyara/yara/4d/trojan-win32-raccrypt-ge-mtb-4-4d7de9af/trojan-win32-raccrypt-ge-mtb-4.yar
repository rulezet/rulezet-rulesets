rule Trojan_Win32_Raccrypt_GE_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {8a 84 32 36 23 01 00 88 04 31 81 c4 ?? ?? 00 00 c3 } 		$a_02_1 = {c1 ea 05 03 d5 [0-05] c7 05 ?? ?? ?? ?? b4 02 d7 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24 } 		$a_02_2 = {51 c7 04 24 02 00 00 00 8b 44 24 ?? ?? 01 04 24 83 2c 24 ?? 8b 04 24 31 01 59 c2 } 		$a_02_3 = {81 ec 00 01 00 00 c7 84 24 ?? ?? ?? ?? 57 78 d1 51 c7 84 24 ?? ?? ?? ?? 0b 4c 1b 7e c7 44 24 ?? dd 0b fa 64 c7 44 24 ?? cf 72 b2 3d c7 84 24 ?? ?? ?? ?? e9 0e 74 64 c7 44 24 ?? a9 53 5d 16 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=21
 
}