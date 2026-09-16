rule Trojan_Win32_Meterpreter_O_4{
	meta:
		description = "Trojan:Win32/Meterpreter.O,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a 4d 31 c9 48 31 c0 ac 3c 61 7c 02 2c 20 41 c1 c9 0d 41 01 c1 e2 ed 52 41 51 48 8b 52 20 8b 42 3c 48 01 d0 8b 80 88 00 00 00 48 85 c0 74 } 		$a_03_1 = {ff e0 58 41 59 5a 48 8b 12 e9 ?? ?? ?? ?? 5d 48 ba 01 00 00 00 00 00 00 00 48 8d 8d ?? ?? 00 00 41 ba 31 8b 6f 87 ff d5 bb f0 b5 a2 56 41 ba a6 95 bd 9d ff d5 } 		$a_01_2 = {bb 47 13 72 6f 6a 00 59 41 89 da ff d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}