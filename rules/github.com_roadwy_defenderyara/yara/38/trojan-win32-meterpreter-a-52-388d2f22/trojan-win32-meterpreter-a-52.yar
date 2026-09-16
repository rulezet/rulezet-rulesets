rule Trojan_Win32_Meterpreter_A__52{
	meta:
		description = "Trojan:Win32/Meterpreter.A!!Meterpreter.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {4d 5a 41 52 55 48 89 e5 48 83 ec 20 48 83 e4 f0 e8 00 00 00 00 5b 48 81 c3 ?? ?? ?? ?? ff d3 48 81 c3 ?? ?? ?? ?? 48 89 3b 49 89 d8 6a 04 5a ff d0 } 		$a_01_1 = {48 8b 9c 24 88 00 00 00 48 63 73 3c 33 c9 41 b8 00 30 00 00 48 03 f3 44 8d 49 40 8b 56 50 41 ff d6 8b 56 50 48 8b c8 48 8b f8 41 ff d7 8b 56 54 48 8b cb 41 bb 01 00 00 00 48 85 d2 74 14 4c 8b c7 4c 2b c3 8a 01 41 88 04 08 49 03 cb 49 2b d3 75 f2 44 0f b7 4e 06 0f b7 46 14 4d 85 c9 74 38 48 8d 4e 2c 48 03 c8 8b 51 f8 44 8b 01 44 8b 51 fc 48 03 d7 4c 03 c3 4d 2b cb 4d 85 d2 74 10 41 8a 00 4d 03 c3 88 02 49 03 d3 4d 2b d3 75 f0 } 		$a_01_2 = {41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 66 81 78 18 0b 02 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}