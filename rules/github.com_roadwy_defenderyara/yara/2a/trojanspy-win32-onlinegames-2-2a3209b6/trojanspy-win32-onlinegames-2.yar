rule TrojanSpy_Win32_OnLineGames_2{
	meta:
		description = "TrojanSpy:Win32/OnLineGames,SIGNATURE_TYPE_PEHSTR,15 00 15 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 4c 4c 2e 64 6c 6c 00 41 6c 70 68 61 42 6c 65 6e 64 00 44 6c 6c } 		$a_01_1 = {54 53 53 61 66 65 45 64 69 74 2e 64 61 74 } 		$a_01_2 = {4d 50 53 6f 63 6b 4c 69 62 } 		$a_01_3 = {4d 50 47 6f 6f 64 53 74 61 74 75 73 } 		$a_01_4 = {47 45 54 00 52 65 66 65 72 65 72 00 71 64 5f 62 61 6c 61 6e 63 65 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=21
 
}