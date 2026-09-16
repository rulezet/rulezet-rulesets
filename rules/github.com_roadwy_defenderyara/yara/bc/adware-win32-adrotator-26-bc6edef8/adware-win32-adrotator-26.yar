rule Adware_Win32_AdRotator_26{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 28 7a c3 3f 19 c6 44 24 30 aa c6 44 24 31 57 c6 44 24 32 1a c6 44 24 33 cd c6 44 24 34 87 c6 44 24 35 c2 c6 44 24 36 6b c6 44 24 37 66 } 		$a_03_1 = {74 0c 8d 64 24 00 80 00 ?? 40 3b c1 75 f8 } 		$a_01_2 = {fe c9 8a d0 fe c0 3a d1 } 		$a_01_3 = {8a c8 fe c0 8a 14 32 3a d1 a2 } 		$a_03_4 = {fe c8 fe c9 a2 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 3a c1 } 		$a_03_5 = {fe c0 fe c9 3a c1 a2 ?? ?? ?? ?? 88 0d } 		$a_01_6 = {2a d0 2a d9 3a da a2 } 		$a_03_7 = {fe c0 fe c9 fe c8 fe c9 a2 ?? ?? ?? ?? 88 0d } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1) >=11
 
}