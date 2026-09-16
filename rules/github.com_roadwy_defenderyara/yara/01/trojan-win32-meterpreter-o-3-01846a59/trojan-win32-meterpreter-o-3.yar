rule Trojan_Win32_Meterpreter_O_3{
	meta:
		description = "Trojan:Win32/Meterpreter.O,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {65 48 8b 52 60 [0-04] 48 8b 52 18 [0-04] 48 8b 52 20 } 		$a_01_1 = {6a 40 41 59 68 00 10 00 00 41 58 48 89 f2 48 31 c9 41 ba 58 a4 53 e5 ff d5 } 		$a_01_2 = {6a 00 48 89 f9 41 ba ad 9e 5f bb ff d5 } 		$a_01_3 = {6a 00 59 49 c7 c2 f0 b5 a2 56 ff d5 } 		$a_01_4 = {5c 5c 2e 5c 70 69 70 65 5c } 		$a_01_5 = {6a 00 59 bb e0 1d 2a 0a 41 89 da ff d5 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}