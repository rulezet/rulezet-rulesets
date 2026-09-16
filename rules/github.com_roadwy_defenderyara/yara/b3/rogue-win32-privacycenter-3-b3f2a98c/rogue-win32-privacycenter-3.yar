rule Rogue_Win32_PrivacyCenter_3{
	meta:
		description = "Rogue:Win32/PrivacyCenter,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {49 6e 73 74 61 6c 6c 61 74 69 6f 6e 00 ?? ?? ?? 00 63 68 65 63 6b 2e 65 78 65 } 		$a_01_1 = {2e 65 78 65 00 64 6f 77 6e 6c 6f 61 64 00 68 74 74 70 3a } 		$a_01_2 = {6d 35 73 6f 66 74 2f 69 6e 73 74 61 6c 6c } 		$a_01_3 = {72 32 73 6f 66 74 2f 69 6e 73 74 61 6c 6c 2d } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}