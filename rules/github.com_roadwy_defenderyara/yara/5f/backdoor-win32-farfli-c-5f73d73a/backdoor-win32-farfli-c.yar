rule Backdoor_Win32_Farfli_C{
	meta:
		description = "Backdoor:Win32/Farfli.C,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 "
		
	strings :
		$a_02_0 = {68 00 00 01 c0 ff 75 08 ff 15 ?? ?? 40 00 8b f0 83 fe ff 75 04 33 c0 eb 1d 8d 45 f0 50 8d 45 e8 50 8d 45 e0 50 } 		$a_00_1 = {80 c9 ff 2a 08 47 3b fe 88 08 72 ee 33 ff } 		$a_02_2 = {b9 ff 00 00 00 2b c8 8b 85 ?? ?? ff ff 88 88 ?? ?? 43 00 eb c5 83 a5 ?? ?? ff ff 00 eb 0d 8b 85 ?? ?? ff ff 40 89 85 } 		$a_00_3 = {0f 84 08 00 00 00 0f 85 02 00 00 00 eb } 		$a_00_4 = {0f 84 0a 00 00 00 0f 85 04 00 00 00 eb } 		$a_00_5 = {0f 84 0e 00 00 00 0f 85 08 00 00 00 eb } 		$a_00_6 = {0f 84 14 00 00 00 0f 85 0e 00 00 00 eb } 	condition:
		((#a_02_0  & 1)*4+(#a_00_1  & 1)*4+(#a_02_2  & 1)*4+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=9
 
}