rule Adware_Win32_AdRotator_7{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {7a c3 3f 19 c7 45 d6 29 4d aa 57 c7 45 da 1a cd 87 c2 66 c7 45 de 6b 66 } 		$a_01_1 = {74 09 8b 06 53 57 56 ff 10 eb 54 } 		$a_03_2 = {8b 44 24 04 eb 04 80 00 ?? 40 3b 44 24 08 75 f6 c2 08 00 } 		$a_01_3 = {66 8b 34 01 66 33 70 fe 66 89 30 83 c0 02 4a 75 ef } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}