rule Rogue_Win32_PrivacyCenter_17{
	meta:
		description = "Rogue:Win32/PrivacyCenter,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {23 5c 43 43 65 6e 74 65 72 00 } 		$a_01_1 = {61 70 2e 65 78 65 00 73 70 2e 65 78 65 00 73 65 74 74 69 6e 67 73 2e 69 6e 69 } 		$a_01_2 = {2f 6e 65 77 69 6e 73 74 61 6c 6c 2f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}