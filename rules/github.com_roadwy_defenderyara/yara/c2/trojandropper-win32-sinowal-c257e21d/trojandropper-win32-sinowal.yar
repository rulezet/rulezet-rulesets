rule TrojanDropper_Win32_Sinowal{
	meta:
		description = "TrojanDropper:Win32/Sinowal,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 09 00 05 00 00 "
		
	strings :
		$a_00_0 = {51 51 0f 01 4c 24 00 8b 44 24 02 59 59 c3 } 		$a_00_1 = {25 00 00 00 ff 33 c9 3d 00 00 00 80 0f 95 c1 8b c1 c3 } 		$a_00_2 = {8b 44 24 08 83 f8 01 7e 90 01 01 8b 4c 24 04 53 56 57 8d 78 fe d1 ef 8d 71 01 47 83 3d 10 30 40 00 00 } 		$a_00_3 = {6a 20 59 56 8b c1 99 6a 10 5e f7 fe 8b c2 83 f8 01 74 0e 83 c1 20 81 f9 a0 0c 00 00 7c e6 33 c0 40 } 		$a_02_4 = {83 ec 10 8d 45 f0 50 ff 15 ?? ?? 40 00 33 c0 8a 45 f1 2c 74 } 	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*3+(#a_02_4  & 1)*3) >=9
 
}