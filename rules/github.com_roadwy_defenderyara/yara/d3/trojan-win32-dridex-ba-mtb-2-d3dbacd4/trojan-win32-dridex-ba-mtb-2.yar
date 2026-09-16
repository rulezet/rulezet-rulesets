rule Trojan_Win32_Dridex_BA_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 55 d8 01 02 8b 45 c8 03 45 a8 2d 67 2b 00 00 03 45 e8 8b 55 d8 31 02 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 } 		$a_81_1 = {74 67 6b 67 65 74 68 6a 72 6e 67 65 77 75 62 34 79 68 32 32 32 31 75 6a 6d 65 74 72 66 76 31 65 74 37 33 34 74 64 63 77 31 36 73 78 71 61 31 7a } 	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}