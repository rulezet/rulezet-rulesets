rule TrojanSpy_Win32_Banker_AJO{
	meta:
		description = "TrojanSpy:Win32/Banker.AJO,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_01_0 = {7a 7a 63 30 4b 4c 30 52 7a 4f 45 42 77 43 41 62 4f 35 41 65 75 49 44 58 6d 42 } 		$a_01_1 = {47 44 67 59 49 7a 62 36 54 6f 4b } 		$a_01_2 = {32 d1 88 54 38 ff 8b 04 24 0f b6 44 38 ff 66 03 f0 66 69 c6 6d ce 66 05 bf 58 8b f0 } 		$a_01_3 = {47 42 20 50 6c 75 67 69 6e 20 49 6e 73 74 61 6c 61 64 6f 2e } 		$a_01_4 = {4d 61 71 75 69 6e 61 20 73 65 6d 20 41 6e 74 56 69 72 75 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=21
 
}