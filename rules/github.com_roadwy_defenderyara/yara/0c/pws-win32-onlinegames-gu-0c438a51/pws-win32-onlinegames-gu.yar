rule PWS_Win32_OnLineGames_GU{
	meta:
		description = "PWS:Win32/OnLineGames.GU,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7b 25 73 7d 00 00 00 00 50 41 53 53 5f 4e 4f 44 33 32 5f 4f 4b 00 00 00 5f 4c 4f 41 44 4c 49 42 52 41 52 59 5f 44 55 4d 4d 59 00 00 25 73 2e 66 6f 6e 00 00 25 73 5c 66 6f 6e 74 73 5c 25 73 2e 66 6f 6e 00 25 73 5c 73 79 73 74 65 6d 00 00 00 } 		$a_01_1 = {43 72 65 61 74 65 4d 75 74 65 78 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}