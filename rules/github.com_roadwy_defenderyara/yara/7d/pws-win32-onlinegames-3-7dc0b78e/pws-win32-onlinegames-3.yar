rule PWS_Win32_OnLineGames_3{
	meta:
		description = "PWS:Win32/OnLineGames,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {9c fb 12 00 a4 fc 12 00 89 10 40 00 00 00 e4 77 b8 ff 12 00 95 7b 41 00 00 00 00 00 bf 7b 41 00 26 00 00 00 b8 ff 12 00 c8 7b 41 00 a4 fd 12 00 00 00 00 00 00 00 00 00 00 00 00 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 44 72 69 76 65 72 73 5c 75 73 62 4b 65 79 49 6e 69 74 2e 73 79 73 00 00 00 00 00 00 00 00 00 00 } 		$a_00_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6b 6e 6c 45 78 74 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}