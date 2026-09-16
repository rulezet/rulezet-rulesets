rule Backdoor_Win32_Venik_G{
	meta:
		description = "Backdoor:Win32/Venik.G,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 ea ?? 80 f2 ?? 88 14 01 41 3b [0-04] 7c } 		$a_03_1 = {fe ff ff 53 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 72 c6 85 ?? fe ff ff 76 c6 85 ?? fe ff ff 69 c6 85 ?? fe ff ff 63 c6 85 ?? fe ff ff 65 c6 85 ?? fe ff ff 73 c6 85 ?? fe ff ff 5c c6 85 ?? fe ff ff 25 c6 85 ?? fe ff ff 73 88 9d ?? fe ff ff } 		$a_01_2 = {49 6e 73 74 61 6c 6c 54 69 6d 65 00 25 34 64 2d 25 2e 32 64 2d 25 2e 32 64 20 25 2e 32 64 3a 25 2e 32 64 00 25 64 2a 25 73 4d 48 7a 00 } 		$a_01_3 = {53 65 63 75 72 69 74 79 00 00 00 00 41 70 70 6c 69 63 61 74 69 6f 6e 00 70 75 6f 72 47 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}