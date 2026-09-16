rule Trojan_Win32_FakeSysdef_15{
	meta:
		description = "Trojan:Win32/FakeSysdef,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 56 c7 45 fc 58 75 01 00 8b 45 fc 8b 4d fc 83 e9 01 89 4d fc 85 c0 } 		$a_01_1 = {be 58 62 40 00 6a 02 8b 36 68 00 70 40 00 68 90 77 40 00 4e ff d6 83 c4 0c } 		$a_01_2 = {c7 85 c4 fe ff ff 6d 6f 10 00 c7 85 dc fe ff ff d9 e2 12 00 c7 85 e0 fe ff ff 81 77 09 00 c7 85 d4 fe ff ff 6e 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}