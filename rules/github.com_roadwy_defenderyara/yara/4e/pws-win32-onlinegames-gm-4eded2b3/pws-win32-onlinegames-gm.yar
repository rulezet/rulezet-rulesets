rule PWS_Win32_OnLineGames_GM{
	meta:
		description = "PWS:Win32/OnLineGames.GM,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 55 4e 49 54 } 		$a_01_1 = {5c 63 6f 6d 72 65 73 72 65 61 6c 2e 64 6c 6c } 		$a_01_2 = {5c 6d 79 5f 73 66 63 5f 6f 73 2e 64 6c 6c } 		$a_01_3 = {68 65 64 67 65 70 69 67 2e 64 61 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2) >=4
 
}