rule TrojanSpy_Win32_Bancos_VN{
	meta:
		description = "TrojanSpy:Win32/Bancos.VN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {31 43 6c 69 63 6b 13 00 [0-08] 49 6d 61 67 65 90 10 03 00 43 6c 69 63 6b } 		$a_00_1 = {4d 65 6e 73 61 67 65 6d 20 64 61 20 70 e1 67 69 6e 61 20 64 61 20 77 65 62 00 00 00 49 6e 73 74 61 6c 61 e7 e3 6f 20 65 6d 20 61 6e 64 61 6d 65 6e 74 6f 2e } 		$a_00_2 = {5c 57 69 6e 64 6f 77 73 5c 53 43 52 2e 6a 70 67 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}