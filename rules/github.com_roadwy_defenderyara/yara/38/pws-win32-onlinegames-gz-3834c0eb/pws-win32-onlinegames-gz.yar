rule PWS_Win32_OnLineGames_GZ{
	meta:
		description = "PWS:Win32/OnLineGames.GZ,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 6c 4d 61 69 6e 2e 64 6c 6c 00 4d 79 44 6c 6c 52 75 6e 00 53 65 72 76 69 63 65 4d 61 69 6e 00 58 69 65 5a 61 69 44 4c 4c } 		$a_01_1 = {77 77 77 2e 78 69 61 6f 68 75 61 2e 6b 72 3a 38 30 30 31 } 		$a_01_2 = {4e 65 74 42 6f 74 20 41 74 74 61 63 6b 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}