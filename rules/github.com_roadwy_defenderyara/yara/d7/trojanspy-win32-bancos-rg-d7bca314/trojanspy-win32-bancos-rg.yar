rule TrojanSpy_Win32_Bancos_RG{
	meta:
		description = "TrojanSpy:Win32/Bancos.RG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5f 4e 65 78 74 50 61 72 74 5f 32 61 6c 74 72 66 6b } 		$a_01_1 = {2f 63 68 61 76 65 2e 74 78 74 } 		$a_01_2 = {63 61 6d 70 6f 20 73 6f 6c 69 63 69 74 61 64 6f 2e } 		$a_01_3 = {53 65 6e 68 61 20 64 65 20 34 20 64 69 67 69 74 6f 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}