rule PWS_Win32_OnLineGames_IT_2{
	meta:
		description = "PWS:Win32/OnLineGames.IT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 64 69 6e 70 75 74 38 5f 2e 64 6c 6c } 		$a_01_1 = {b0 73 c6 44 24 39 66 52 88 44 24 3c c6 44 24 3e 63 c6 44 24 3f 5f c6 44 24 40 6f 88 44 24 41 c6 44 24 42 2e c6 44 24 43 64 c6 44 24 44 6c c6 44 24 45 6c 88 5c 24 46 ff } 		$a_03_2 = {c6 44 24 2c 6c c6 44 24 2d 7a c6 44 24 2e 67 c6 44 24 2f 2e 88 ?? 24 ?? 88 ?? 24 33 89 ?? 24 3c c6 44 24 18 6c c6 44 24 19 7a c6 44 24 1a 67 c6 44 24 1b 31 c6 44 24 1c 2e 88 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}