rule Trojan_Win32_FakeSysdef_14{
	meta:
		description = "Trojan:Win32/FakeSysdef,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 56 c7 45 fc 68 83 01 00 8b 45 fc 8b 4d fc 83 e9 01 89 4d fc 85 c0 } 		$a_01_1 = {6a 00 be 08 62 40 00 8b 36 6a 43 ff d6 } 		$a_01_2 = {c7 45 cc fa 0c 00 00 c7 45 e4 00 00 00 00 c7 45 e8 d4 81 01 00 c7 45 dc 0b 00 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}