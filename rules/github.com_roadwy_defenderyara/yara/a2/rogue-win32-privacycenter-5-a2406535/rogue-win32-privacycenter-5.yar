rule Rogue_Win32_PrivacyCenter_5{
	meta:
		description = "Rogue:Win32/PrivacyCenter,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {19 1d 1f 20 29 33 2e 2f 34 34 36 3b 35 01 01 a3 94 8f 8f 8f 8f 8f 8f 8f 93 93 8a 8e 8e 97 96 a2 } 		$a_01_1 = {d6 dc d9 da d9 d7 dc d3 d3 df d0 d4 e9 d2 dc f8 dc e7 ff dd e7 ff db da df e2 d9 d8 79 b5 9b 93 } 		$a_03_2 = {ba fd 00 00 00 e8 ?? ?? ?? ?? 8b c3 ba 14 00 00 00 } 		$a_01_3 = {74 68 65 20 6c 61 73 74 65 73 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*3+(#a_01_3  & 1)*3) >=4
 
}