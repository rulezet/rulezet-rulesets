rule Trojan_Win32_Meterpreter_A__12{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff e0 5f 5f 5a 8b 12 eb ?? 5d 6a 01 8d 85 9a 00 00 00 50 68 31 8b 6f 87 ff d5 68 47 13 72 6f ff d5 } 		$a_01_1 = {60 89 e5 31 c0 64 8b 50 30 8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 52 57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3 48 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}