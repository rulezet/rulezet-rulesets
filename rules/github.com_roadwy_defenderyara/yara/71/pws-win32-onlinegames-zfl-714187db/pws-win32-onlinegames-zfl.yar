rule PWS_Win32_OnLineGames_ZFL{
	meta:
		description = "PWS:Win32/OnLineGames.ZFL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 53 6a 10 57 ff d6 53 53 6a 12 57 ff d6 53 53 } 		$a_02_1 = {64 62 72 25 30 32 78 2a 2e ?? ?? ?? 00 } 		$a_00_2 = {00 5f 5f 25 73 5f 25 73 5f 25 64 5f 00 } 		$a_00_3 = {00 5f 5f 25 73 5f 25 64 5f 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}