rule Trojan_Win32_Startpage_AEL{
	meta:
		description = "Trojan:Win32/Startpage.AEL,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 78 69 68 61 6f 2e 6e 65 74 2f 30 33 33 2f 74 61 6f 62 61 6f 2e 68 74 6d 6c } 		$a_01_1 = {5c d7 c0 c3 e6 5c cc d4 b1 a6 2d cc d8 c2 f4 2e } 		$a_01_2 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 00 } 		$a_01_3 = {00 53 74 61 72 74 20 50 61 67 65 00 } 		$a_01_4 = {68 6f 6f 6b 2e 64 6c 6c } 		$a_01_5 = {74 61 6f 62 61 6f 2e 69 63 6f 27 } 		$a_01_6 = {5c 6c 76 65 67 6e 65 64 5c 63 6f 6e 66 69 67 2e 69 6e 69 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}