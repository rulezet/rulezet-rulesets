rule Trojan_Win32_Meterpreter_gen_C_5{
	meta:
		description = "Trojan:Win32/Meterpreter.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 2d 06 18 7b ff d5 85 c0 75 } 		$a_03_1 = {53 56 68 12 96 89 e2 ff d5 85 c0 74 ?? 8b 07 01 c3 85 c0 75 } 		$a_01_2 = {68 6e 65 74 00 68 77 69 6e 69 54 68 4c 77 26 07 ff d5 } 		$a_01_3 = {68 3a 56 79 a7 ff d5 } 		$a_01_4 = {68 58 a4 53 e5 ff d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}