rule Trojan_Win32_Oficla_E_2{
	meta:
		description = "Trojan:Win32/Oficla.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 2c 13 04 18 5d 8d 85 ?? ?? ?? ?? ff d0 85 c0 75 04 } 		$a_03_1 = {c7 44 24 2c 8b f7 08 3e 8d 85 ?? ?? ?? ?? ff d0 8b 54 24 40 52 ff d0 } 		$a_03_2 = {0f b6 02 83 ?? 01 83 c2 01 33 05 ?? ?? ?? ?? 88 03 83 c3 01 3b ?? 48 77 ff ff 75 e4 } 		$a_01_3 = {83 c0 01 89 44 24 08 69 c2 b7 c6 05 00 0f af d1 8d 75 f3 89 44 24 04 0f b6 c3 01 d0 89 04 24 e8 } 		$a_01_4 = {8b 45 0c 8b 5d 08 c7 44 24 04 c9 f8 00 00 c7 04 24 00 00 00 00 89 44 24 08 e8 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}