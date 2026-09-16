rule TrojanSpy_iPhoneOS_Ftikser_A{
	meta:
		description = "TrojanSpy:iPhoneOS/Ftikser.A,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {66 75 63 6b 5f 69 70 68 6f 6e 65 } 		$a_03_1 = {78 73 73 65 72 2e 63 6f 6d [0-10] 38 30 [0-10] 25 40 3a 25 40 2f 43 68 65 63 6b 4c 69 62 72 61 72 79 2e 61 73 70 78 } 		$a_03_2 = {48 74 74 70 46 75 6e 4d 61 69 6e [0-10] 77 72 69 74 65 54 6f 46 69 6c 65 3a 61 74 6f 6d 69 63 61 6c 6c 79 } 		$a_01_3 = {2f 62 69 6e 2f 25 40 00 44 6f 77 6e 6c 6f 61 64 69 6e 67 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}