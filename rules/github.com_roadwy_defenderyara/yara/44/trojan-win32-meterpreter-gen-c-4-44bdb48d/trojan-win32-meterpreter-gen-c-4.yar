rule Trojan_Win32_Meterpreter_gen_C_4{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff } 		$a_03_1 = {5c 5c 2e 5c 70 69 70 65 [0-20] 68 da f6 da 4f ff d5 } 		$a_01_2 = {68 58 a4 53 e5 ff d5 } 		$a_01_3 = {68 ad 9e 5f bb ff d5 } 		$a_01_4 = {68 0b 2f 0f 30 ff d5 57 68 c6 96 87 52 ff d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}