rule Trojan_Win32_CobaltStrike_A__5{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 b9 00 10 00 00 4c 8d 87 80 00 00 00 48 89 d6 c7 44 24 20 04 00 00 00 31 d2 ff 15 ?? ?? ?? ?? 48 89 c5 48 8d 44 24 50 4d 89 e0 49 89 f9 48 89 ea 48 89 d9 48 89 44 24 20 ff 15 } 		$a_01_1 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00 } 		$a_01_2 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}