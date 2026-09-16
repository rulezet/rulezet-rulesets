rule Trojan_Win32_Silentbanker_B_2{
	meta:
		description = "Trojan:Win32/Silentbanker.B,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 14 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 04 8d 0c 40 8d 0c 88 c1 e1 04 03 c8 c1 e1 08 2b c8 8d 84 88 c3 9e 26 00 8b c8 c1 e9 10 0f af ca c1 e9 10 74 dc a3 ?? ?? ?? ?? 8b c1 c2 04 00 90 09 0f 00 a1 ?? ?? ?? ?? 85 c0 75 06 ff 15 } 		$a_02_1 = {b9 fb 03 00 00 b8 20 20 20 20 bf ?? ?? ?? ?? f3 ab 66 ab bf ee 0f 00 00 c7 44 24 10 00 00 00 00 8b 44 24 10 8b 74 24 1c d1 e8 f6 c4 01 89 44 24 10 75 1b } 		$a_00_2 = {25 73 25 78 25 78 2e 64 61 74 } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*10) >=20
 
}