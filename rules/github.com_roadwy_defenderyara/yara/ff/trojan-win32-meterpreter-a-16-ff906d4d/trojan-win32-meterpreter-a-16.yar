rule Trojan_Win32_Meterpreter_A__16{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 ba 02 d9 c8 5f ff d5 } 		$a_01_1 = {41 ba 75 6e 4d 61 ff d5 } 		$a_01_2 = {41 ba 58 a4 53 e5 ff d5 } 		$a_01_3 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 } 		$a_01_4 = {5d 49 be 77 73 32 5f 33 32 00 00 41 56 } 		$a_03_5 = {41 ba ea 0f df e0 ff d5 [0-20] 41 ba 99 a5 74 61 ff d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=4
 
}