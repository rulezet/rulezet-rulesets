rule PWS_Win32_OnLineGames_KZ{
	meta:
		description = "PWS:Win32/OnLineGames.KZ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {4b 4a 44 4a 53 4b 4b 57 } 		$a_02_1 = {c6 45 e4 6f c6 45 ?? 03 c6 45 ?? 17 c6 45 ?? 1b c6 45 ?? 6d c6 45 ?? 18 c6 45 ?? 0f } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}