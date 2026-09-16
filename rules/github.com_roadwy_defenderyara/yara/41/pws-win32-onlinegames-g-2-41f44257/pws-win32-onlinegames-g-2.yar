rule PWS_Win32_OnLineGames_G_2{
	meta:
		description = "PWS:Win32/OnLineGames.G,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 64 64 72 25 73 68 65 6c 70 } 		$a_00_1 = {71 64 73 68 6d 2e 64 6c 6c } 		$a_01_2 = {55 75 69 64 43 72 65 61 74 65 } 		$a_01_3 = {57 53 43 57 72 69 74 65 50 72 6f 76 69 64 65 72 4f 72 64 65 72 } 		$a_00_4 = {55 8b ec 81 ec 3c 06 00 00 53 90 8b d2 8b c0 90 8b d2 90 8b db 90 8b c9 90 90 8b d2 8b c0 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*10) >=14
 
}