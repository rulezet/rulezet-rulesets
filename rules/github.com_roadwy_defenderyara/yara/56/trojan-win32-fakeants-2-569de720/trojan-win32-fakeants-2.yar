rule Trojan_Win32_FakeAnts_2{
	meta:
		description = "Trojan:Win32/FakeAnts,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a c8 80 c1 51 30 88 ?? ?? 00 10 83 c0 01 3d } 		$a_03_1 = {75 31 83 c6 04 81 fe ?? ?? ?? ?? 72 e4 8b 44 24 24 8b 4c 24 20 8b 54 24 1c } 		$a_01_2 = {64 6f 5f 64 6c 6c 2e 64 6c 6c 00 49 } 		$a_01_3 = {77 69 6e 6c 6f 67 6f 6e 2e 73 79 73 00 } 		$a_03_4 = {8b 7c 24 10 b9 06 00 00 00 be 38 20 40 00 f3 a5 90 09 17 00 30 20 40 00 ?? ?? ?? ?? ?? 10 30 40 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*3) >=3
 
}