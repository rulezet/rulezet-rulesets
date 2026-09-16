rule Trojan_Win32_CobaltStrike_A__7{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {41 b8 00 30 00 00 31 c9 48 89 f7 ff 15 ?? ?? ?? ?? 48 89 c3 31 c0 39 f8 7d 16 48 89 c2 83 e2 03 41 8a 14 14 32 54 05 00 88 14 03 48 ff c0 eb e6 } 		$a_01_1 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00 } 		$a_03_2 = {b9 60 ea 00 00 ff d3 eb f7 [0-10] 48 ff e1 } 		$a_01_3 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}