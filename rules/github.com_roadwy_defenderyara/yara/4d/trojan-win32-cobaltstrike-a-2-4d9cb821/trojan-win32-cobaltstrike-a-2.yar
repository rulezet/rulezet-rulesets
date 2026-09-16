rule Trojan_Win32_CobaltStrike_A__2{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 52 55 48 89 e5 48 81 ec 20 00 00 00 48 8d 1d ea ff ff ff 48 89 df 48 81 c3 ?? ?? ?? ?? ff d3 41 b8 ?? ?? ?? ?? 68 04 00 00 00 5a 48 89 f9 ff d0 00 00 00 00 00 00 00 00 } 		$a_01_1 = {41 b9 00 30 00 00 4d 8b c7 33 d2 48 8b cf c7 44 24 20 40 00 00 00 ff 15 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}