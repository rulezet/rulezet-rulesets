rule PWS_Win32_OnLineGames_CJ_2{
	meta:
		description = "PWS:Win32/OnLineGames.CJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 64 6c 6c 00 68 6f 6f 6b 6f 66 66 00 68 6f 6f 6b 6f 6e } 		$a_03_1 = {6a 00 52 8d ?? ?? ?? ?? 00 00 68 14 01 00 00 50 56 ff 15 24 20 40 00 } 		$a_03_2 = {68 b8 0b 00 00 f3 ab ff 15 ?? ?? 40 00 8d ?? ?? ?? 51 68 04 01 00 00 ff 15 ?? ?? 40 00 8d ?? ?? ?? 68 ?? ?? 40 00 52 ff 15 ?? ?? 40 00 8d ?? ?? ?? 50 6a 6b e8 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}