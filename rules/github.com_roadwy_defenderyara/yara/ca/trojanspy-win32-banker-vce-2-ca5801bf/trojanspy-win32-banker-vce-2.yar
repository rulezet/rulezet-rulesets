rule TrojanSpy_Win32_Banker_VCE_2{
	meta:
		description = "TrojanSpy:Win32/Banker.VCE,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 23 74 75 61 23 6c 69 7a 61 63 23 61 6f 2e 65 23 78 65 } 		$a_01_1 = {70 23 61 23 73 23 73 23 77 25 64 25 } 		$a_01_2 = {6c 2a 23 6f 67 23 69 6e } 		$a_01_3 = {68 74 23 74 70 3a 2f 2f 6c 6f 23 67 69 6e 2e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}