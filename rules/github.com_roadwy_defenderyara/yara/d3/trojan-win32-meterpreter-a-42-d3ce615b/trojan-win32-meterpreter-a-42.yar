rule Trojan_Win32_Meterpreter_A__42{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {4d 5a e8 00 00 00 00 5b 52 45 55 89 e5 81 c3 ?? ?? ?? ?? ff d3 81 c3 ?? ?? ?? ?? 89 3b 53 6a 04 50 ff d0 } 		$a_01_1 = {8b 75 fc 8b 5e 3c 6a 40 03 de 68 00 30 00 00 89 5d f0 ff 73 50 6a 00 ff 55 ec ff 73 50 8b f8 57 89 7d f4 ff 55 e8 8b 53 54 8b ce 85 d2 74 12 8b c7 2b c6 89 45 d8 8b f0 8a 01 88 04 0e 41 4a 75 f7 } 		$a_01_2 = {41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}