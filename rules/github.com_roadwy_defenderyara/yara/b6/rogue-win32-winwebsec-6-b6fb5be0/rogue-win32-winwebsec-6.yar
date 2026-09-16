rule Rogue_Win32_Winwebsec_6{
	meta:
		description = "Rogue:Win32/Winwebsec,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 00 27 00 6d 00 20 00 68 00 65 00 72 00 65 00 00 00 } 		$a_03_1 = {8d 45 f4 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 8b 35 ?? ?? ?? ?? 8b 36 8d 55 f0 b8 ?? ?? ?? ?? ff d6 8b 45 f0 e8 } 		$a_03_2 = {6a 00 6a 01 6a 13 e8 ?? ?? ?? ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 0f b6 c3 50 e8 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}