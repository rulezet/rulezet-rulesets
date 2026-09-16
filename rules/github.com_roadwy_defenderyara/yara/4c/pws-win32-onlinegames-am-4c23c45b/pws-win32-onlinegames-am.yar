rule PWS_Win32_OnLineGames_AM{
	meta:
		description = "PWS:Win32/OnLineGames.AM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {5e 5b 74 0a e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 68 90 90 5f 01 00 ff 15 ?? ?? 40 00 } 		$a_03_1 = {6a 0a 68 c8 00 00 00 56 ff 15 ?? ?? 40 00 85 c0 74 29 50 56 ff 15 ?? ?? 40 00 } 		$a_03_2 = {6a 64 ff d6 e8 ?? ?? ff ff 6a 64 ff d6 e8 ?? ?? ff ff 6a 64 ff d6 eb a6 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*2) >=3
 
}