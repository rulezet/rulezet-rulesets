rule Rogue_Win32_PrivacyCenter_7{
	meta:
		description = "Rogue:Win32/PrivacyCenter,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {74 65 6d 70 2e 65 78 65 20 2d 69 6e 73 74 61 6c 6c } 		$a_00_1 = {39 31 2e 32 30 37 2e 31 31 36 2e 34 34 } 		$a_00_2 = {54 61 68 6f 6d 61 } 		$a_03_3 = {ba 8d 02 00 00 e8 ?? ?? ff ff a1 ?? ?? 40 00 ba c7 01 00 00 e8 ?? ?? ff ff a1 ?? ?? 40 00 e8 ?? ?? ff ff a1 ?? ?? 40 00 b2 01 } 		$a_01_4 = {08 97 c1 00 00 00 50 8b 87 35 01 00 00 29 c8 50 57 8d bf 29 01 00 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}