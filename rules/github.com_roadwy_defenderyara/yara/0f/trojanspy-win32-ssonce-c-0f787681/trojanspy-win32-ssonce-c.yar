rule TrojanSpy_Win32_SSonce_C{
	meta:
		description = "TrojanSpy:Win32/SSonce.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 6b 65 79 6c 6f 67 2e 64 61 74 } 		$a_01_1 = {7c 44 49 52 23 30 23 00 } 		$a_00_2 = {73 74 75 62 70 61 74 68 00 } 		$a_00_3 = {5b 73 68 69 66 74 5d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}