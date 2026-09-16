rule Trojan_Win32_Meterpreter_A__29{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3b 7d 24 75 e4 58 8b 58 24 01 d3 66 8b 0c 4b 8b 58 1c 01 d3 8b 04 8b 01 d0 89 44 24 24 5b 5b 61 59 5a 51 ff e0 } 		$a_01_1 = {68 a6 95 bd 9d ff d3 3c 06 7c 1a 31 c9 64 8b 41 18 39 88 a8 01 00 00 75 0c 8d 93 cf 00 00 00 89 90 a8 01 00 00 31 c9 51 51 ff 76 08 ff 36 51 51 68 38 68 0d 16 ff d3 c9 } 		$a_01_2 = {53 74 61 67 65 6c 65 73 73 49 6e 69 74 } 		$a_01_3 = {47 45 54 20 2f 31 32 33 34 35 36 37 38 39 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}