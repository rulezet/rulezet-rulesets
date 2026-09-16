rule Trojan_Win32_FakeSysdef_7{
	meta:
		description = "Trojan:Win32/FakeSysdef,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 66 63 72 79 70 74 5c 52 65 6c 65 61 73 65 5c 53 5c 73 5f 68 69 67 68 2e 70 64 62 } 		$a_03_1 = {3a 5c 73 72 63 5c [0-08] 5c 52 65 6c 65 61 73 65 5c 53 5c } 		$a_10_2 = {0f b7 02 8b c8 81 e1 ff 0f 00 00 03 4c 24 10 4e c1 e8 0c 89 74 24 14 83 f8 03 75 07 } 		$a_12_3 = {df 2b da 8d 9b 00 00 00 00 8b 50 04 8b 08 2b f2 83 c0 08 83 c2 f8 50 d1 ea 03 cf 52 51 e8 90 01 01 00 00 00 90 00 01 } 		$a_8a_4 = {8a c8 80 e9 90 01 01 80 f9 90 01 01 77 90 01 01 66 0f } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_10_2  & 1)*1+(#a_12_3  & 1)*1+(#a_8a_4  & 1)*13568) >=3
 
}