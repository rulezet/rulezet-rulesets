rule PWS_Win32_OnLineGames_IT{
	meta:
		description = "PWS:Win32/OnLineGames.IT,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } 		$a_01_1 = {26 54 42 5f 43 61 72 64 50 61 73 73 77 6f 72 64 32 3d } 		$a_01_2 = {75 73 65 72 64 61 74 61 5c 63 75 72 72 65 6e 74 73 65 72 76 65 72 2e 69 6e 69 } 		$a_01_3 = {45 6c 65 6d 65 6e 74 20 43 6c 69 65 6e 74 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}