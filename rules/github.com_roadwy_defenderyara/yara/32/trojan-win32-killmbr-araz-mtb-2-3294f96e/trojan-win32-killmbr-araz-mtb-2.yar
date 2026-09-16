rule Trojan_Win32_KillMBR_ARAZ_MTB_2{
	meta:
		description = "Trojan:Win32/KillMBR.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 41 50 4d 20 30 38 32 37 39 2b 35 32 35 35 2e 70 64 62 } 		$a_80_1 = {6f 76 65 72 77 72 69 74 65 20 74 68 65 20 62 6f 6f 74 20 72 65 63 6f 72 64 } 		$a_80_2 = {4d 61 6c 77 61 72 65 2c 20 52 75 6e } 		$a_80_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } 	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}