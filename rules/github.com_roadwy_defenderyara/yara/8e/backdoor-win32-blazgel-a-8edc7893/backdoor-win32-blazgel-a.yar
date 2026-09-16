rule Backdoor_Win32_Blazgel_A{
	meta:
		description = "Backdoor:Win32/Blazgel.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {b9 5a 36 c4 01 b8 e2 df 59 38 89 4c 24 3c 89 4c 24 34 89 4c 24 2c 8d 4c 24 28 89 44 24 38 89 44 24 30 89 44 24 28 8d 54 24 30 51 8d 44 24 3c 52 50 53 c7 44 24 3c c2 27 c5 01 ff 15 } 		$a_01_1 = {8d 14 92 d1 e2 48 75 f8 8b fd 83 c9 ff 33 c0 f2 ae b8 1f 85 eb 51 8b 7c 24 10 f7 ea f7 d1 49 c1 fa 05 0f be 0c 19 8b c2 83 e9 30 c1 e8 1f 03 d0 0f af ca 03 f9 4e 43 } 		$a_00_2 = {5c 64 65 6c 2e 62 61 74 } 		$a_00_3 = {5c 5c 2e 5c 75 73 62 6d 6f 75 73 65 62 } 		$a_00_4 = {25 73 20 2d 72 20 22 25 73 } 		$a_00_5 = {4c 6f 61 64 52 6f 6f 74 4b 69 74 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}