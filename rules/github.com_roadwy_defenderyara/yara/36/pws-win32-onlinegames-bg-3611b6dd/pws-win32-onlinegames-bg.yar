rule PWS_Win32_OnLineGames_BG{
	meta:
		description = "PWS:Win32/OnLineGames.BG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 18 56 6a 32 6a 01 ff ?? ?? ff 15 } 		$a_03_1 = {6a 2f 57 ff 15 ?? ?? ?? ?? 40 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 6a 32 } 		$a_01_2 = {25 73 25 73 25 73 } 		$a_00_3 = {6d 69 62 61 6f 2e 61 73 70 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}