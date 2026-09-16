rule Trojan_Win32_CobaltStrike_A__9{
	meta:
		description = "Trojan:Win32/CobaltStrike.A!!CobaltStrike.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 01 6a 02 e8 [0-30] 6a 02 58 ff 75 08 66 89 45 ec e8 [0-40] 6a 78 56 ff 15 } 		$a_03_1 = {8e 4e 0e ec 74 ?? 81 7d ?? aa fc 0d 7c 74 ?? 81 7d ?? 54 ca af 91 74 } 		$a_01_2 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00 } 		$a_01_3 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55 } 		$a_01_4 = {83 7d 9c 40 73 19 0f b6 45 a7 8b 4d 98 03 4d 9c 0f b6 09 33 c8 8b 45 98 03 45 9c 88 08 eb da } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}