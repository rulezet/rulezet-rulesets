rule PWS_Win32_OnLineGames_HS{
	meta:
		description = "PWS:Win32/OnLineGames.HS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 20 61 6d 20 76 69 72 75 73 21 20 46 75 63 6b 20 79 6f 75 20 3a 2d 29 } 		$a_01_1 = {79 65 73 20 26 26 20 6e 65 74 20 75 73 65 72 20 67 75 65 73 74 20 31 32 34 32 37 37 36 36 38 20 26 26 20 6e 65 74 } 		$a_01_2 = {53 75 70 65 72 2d 58 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}