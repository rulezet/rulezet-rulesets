rule PWS_Win32_OnLineGames_HS_2{
	meta:
		description = "PWS:Win32/OnLineGames.HS,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 55 fc 8a 1c 11 80 c3 7a 88 1c 11 8b 55 fc 80 34 11 19 [0-08] 41 3b c8 7c } 		$a_01_1 = {77 49 4e 44 4f 57 53 20 6e 74 5c 63 55 52 52 45 4e 54 76 45 52 53 49 4f 4e 5c 73 56 43 48 4f 53 54 } 		$a_01_2 = {25 73 59 53 54 45 4d 72 4f 4f 54 25 5c 73 59 53 54 45 4d 33 32 5c 53 56 43 48 4f 53 54 2e 45 58 45 20 2d 4b 20 4e 45 54 53 56 43 53 } 		$a_01_3 = {53 75 70 65 72 58 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}