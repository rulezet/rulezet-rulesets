rule Trojan_Win32_Meterpreter_A__19{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 c7 c2 6c 29 24 7e ff d5 } 		$a_01_1 = {49 c7 c2 05 88 9d 70 ff d5 } 		$a_01_2 = {49 ba 95 58 bb 91 00 00 00 00 ff d5 } 		$a_01_3 = {49 ba d3 58 9d ce 00 00 00 00 ff d5 } 		$a_01_4 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 } 		$a_03_5 = {49 be 77 69 6e 68 74 74 70 00 [0-08] 49 c7 c2 4c 77 26 07 ff d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}