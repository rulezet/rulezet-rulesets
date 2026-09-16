rule Trojan_Win32_Meterpreter_A__36{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 52 0c 8b 52 14 8b 72 28 0f b7 4a 26 31 ff ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f2 52 57 8b 52 10 8b 4a 3c 8b 4c 11 78 e3 } 		$a_03_1 = {ff e0 5f 5f 5a 8b 12 eb ?? 5d 6a 01 8d 85 ?? 00 00 00 50 68 31 8b 6f 87 ff d5 bb f0 b5 a2 56 68 a6 95 bd 9d ff d5 } 		$a_01_2 = {bb 47 13 72 6f 6a 00 53 ff d5 } 		$a_03_3 = {ff e0 5f 5f 5a 8b 12 eb 8d 5d 8d 85 ?? 00 00 00 50 68 4c 77 26 07 ff d5 bb f0 b5 a2 56 68 a6 95 bd 9d ff d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}