rule Trojan_Win32_Meterpreter_A__20{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 68 33 32 68 77 73 32 5f 54 66 b9 72 60 ff d6 } 		$a_01_1 = {95 53 53 53 53 43 53 43 53 89 e7 66 81 ef 08 02 57 53 66 b9 e7 df ff d6 } 		$a_01_2 = {66 b9 a8 6f ff d6 97 68 0a 0a 01 15 } 		$a_01_3 = {66 b9 a8 6f ff d6 97 68 c0 a8 01 07 } 		$a_01_4 = {66 53 89 e3 6a 10 53 57 66 b9 57 05 ff d6 } 		$a_01_5 = {50 b4 0c 50 53 57 53 66 b9 c0 38 ff e6 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}