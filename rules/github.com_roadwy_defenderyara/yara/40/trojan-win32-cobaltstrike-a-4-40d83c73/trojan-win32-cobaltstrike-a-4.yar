rule Trojan_Win32_CobaltStrike_A__4{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {ff e0 58 5f 5a 8b 12 eb 86 5b 80 7e 10 00 75 3b c6 46 10 01 68 a6 95 bd 9d ff d3 3c 06 7c 1a } 		$a_01_1 = {31 c9 51 51 ff 76 08 ff 36 51 51 68 38 68 0d 16 ff d3 c9 } 		$a_01_2 = {e8 00 00 00 00 58 83 c0 25 83 ec 08 89 e2 c7 42 04 33 00 00 00 89 02 e8 09 00 00 00 } 		$a_01_3 = {48 31 d2 48 8b 0e 41 ba c8 38 a4 40 ff d5 48 85 c0 74 0c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}