rule PWS_WinNT_OnLineGames_E{
	meta:
		description = "PWS:WinNT/OnLineGames.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 00 1f 00 00 00 56 8b 01 03 c2 0f b6 50 03 0f b6 70 02 } 		$a_01_1 = {8d 34 70 81 fe 02 00 00 01 0f } 		$a_01_2 = {77 73 68 74 63 70 69 70 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}