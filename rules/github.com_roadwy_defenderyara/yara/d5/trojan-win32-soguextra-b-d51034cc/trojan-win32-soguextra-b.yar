rule Trojan_Win32_SoguExtra_B{
	meta:
		description = "Trojan:Win32/SoguExtra.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 0b 00 00 "
		
	strings :
		$a_01_0 = {0f 07 b2 53 } 		$a_01_1 = {ce c9 ca bd } 		$a_01_2 = {43 c9 fc 54 } 		$a_01_3 = {65 00 ba fa } 		$a_01_4 = {18 81 ed 44 } 		$a_01_5 = {3d c6 fb 99 } 		$a_01_6 = {75 e7 11 1a } 		$a_01_7 = {3d 3c c3 c2 } 		$a_01_8 = {f3 21 06 82 } 		$a_01_9 = {a8 2c a6 2f } 		$a_01_10 = {3a fd 80 0e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=3
 
}