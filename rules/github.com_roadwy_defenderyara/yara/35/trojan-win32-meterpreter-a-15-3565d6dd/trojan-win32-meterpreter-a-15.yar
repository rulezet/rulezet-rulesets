rule Trojan_Win32_Meterpreter_A__15{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {0f b7 4a 26 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0 } 		$a_01_1 = {e3 3c 49 8b 34 8b 01 d6 31 ff 31 c0 ac c1 cf 0d 01 c7 38 e0 75 f4 03 7d f8 3b 7d 24 75 e2 } 		$a_01_2 = {50 68 31 8b 6f 87 ff d5 } 		$a_01_3 = {bb e0 1d 2a 0a 68 a6 95 bd 9d ff d5 } 		$a_01_4 = {bb 47 13 72 6f 6a 00 53 ff d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}