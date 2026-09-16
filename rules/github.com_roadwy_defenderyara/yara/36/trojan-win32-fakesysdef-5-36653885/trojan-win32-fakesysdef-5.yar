rule Trojan_Win32_FakeSysdef_5{
	meta:
		description = "Trojan:Win32/FakeSysdef,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 19 51 ff d7 85 c0 74 ?? 8b 16 52 ff 15 ?? ?? ?? ?? 8a 00 8b 0e fe c8 25 ff 00 00 00 } 		$a_03_1 = {6a 19 50 ff d7 85 c0 75 90 14 8b 16 52 ff 15 ?? ?? ?? ?? 8a 00 8b 0e fe c8 25 ff 00 00 00 } 		$a_03_2 = {2b de 66 8b 04 33 55 66 33 44 24 ?? 47 66 89 06 83 c6 02 ff 15 ?? ?? ?? ?? 3b f8 7c e5 } 		$a_03_3 = {52 50 68 02 00 00 80 e8 ?? ?? ?? ?? 83 c4 ?? e8 ?? ?? ?? ?? b9 1f 00 00 00 33 c0 8d bc } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}