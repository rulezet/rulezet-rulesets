rule Trojan_Win32_Dridex_AD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {8d 8a 42 07 00 00 57 8b f8 2b f9 8d 74 3e b6 0f af c6 03 c1 0f af c6 03 c1 8d b4 08 dd 19 ff ff 8a d8 0f af c6 03 c1 } 		$a_80_1 = {4d 6f 73 74 2e 70 64 62 } 		$a_80_2 = {55 6e 72 65 67 69 73 74 65 72 48 6f 74 4b 65 79 } 		$a_80_3 = {47 72 6f 77 6f 74 68 65 72 } 		$a_80_4 = {57 6f 72 64 46 6f 72 63 65 } 	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}