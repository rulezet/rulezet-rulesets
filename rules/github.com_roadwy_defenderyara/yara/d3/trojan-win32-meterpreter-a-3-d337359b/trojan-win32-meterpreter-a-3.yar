rule Trojan_Win32_Meterpreter_A__3{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 6c 6c 20 41 68 33 32 2e 64 68 75 73 65 72 } 		$a_01_1 = {68 6f 78 58 20 68 61 67 65 42 68 4d 65 73 73 } 		$a_01_2 = {8b 45 3c 8b 54 28 78 } 		$a_03_3 = {84 c0 74 07 c1 cf ?? 01 c7 eb f4 3b 7c 24 28 75 e1 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}