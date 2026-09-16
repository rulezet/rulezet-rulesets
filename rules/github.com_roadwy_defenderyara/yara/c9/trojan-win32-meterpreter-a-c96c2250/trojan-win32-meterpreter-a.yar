rule Trojan_Win32_Meterpreter_A_{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 00 68 58 a4 53 e5 ff d5 } 		$a_01_1 = {68 64 6e 73 61 54 68 4c 77 26 07 ff d5 } 		$a_01_2 = {50 68 6a c9 9c c9 ff d5 } 		$a_01_3 = {68 f4 00 8e cc ff d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}