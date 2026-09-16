rule TrojanSpy_Win32_Bancos_UW_2{
	meta:
		description = "TrojanSpy:Win32/Bancos.UW,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 4a 41 53 48 42 46 48 4a 5a 53 56 43 48 53 48 55 49 45 57 54 00 } 		$a_01_1 = {45 48 41 53 55 49 46 42 41 53 48 4a 42 45 52 55 49 54 45 48 52 54 4a 45 00 } 		$a_00_2 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}