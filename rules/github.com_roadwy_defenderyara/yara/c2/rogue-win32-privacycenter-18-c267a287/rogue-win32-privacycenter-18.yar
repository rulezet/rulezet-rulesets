rule Rogue_Win32_PrivacyCenter_18{
	meta:
		description = "Rogue:Win32/PrivacyCenter,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 00 ff ff ff ff 09 00 00 00 41 6e 74 69 76 69 72 75 73 00 00 00 ff ff ff ff 15 00 00 00 53 4f 46 54 57 41 52 45 5c 53 61 66 65 74 79 43 65 6e 74 65 72 00 } 		$a_01_1 = {5c 75 49 45 5f 42 48 4f 2e 70 61 73 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}