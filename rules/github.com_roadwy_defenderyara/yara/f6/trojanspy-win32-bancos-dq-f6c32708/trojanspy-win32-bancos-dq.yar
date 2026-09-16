rule TrojanSpy_Win32_Bancos_DQ{
	meta:
		description = "TrojanSpy:Win32/Bancos.DQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } 		$a_01_1 = {43 3a 5c 41 72 71 75 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 73 5c 47 62 50 6c 75 67 69 6e 5c 67 62 78 2e 73 79 73 } 		$a_80_2 = {52 65 6d 6f 76 65 72 44 65 50 6c 75 67 } 		$a_80_3 = {52 65 6d 6f 76 65 64 6f 72 7a 61 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}