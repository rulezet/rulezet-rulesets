rule Adware_MacOS_Pirrit_C_2{
	meta:
		description = "Adware:MacOS/Pirrit.C,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 72 6f 6a 65 63 74 73 2f 70 69 72 72 69 74 2f 6d 61 63 6f 73 2f 50 72 6f 78 79 53 65 72 76 65 72 } 		$a_00_1 = {74 68 65 63 6c 6f 75 64 73 65 72 76 69 63 65 73 2e 6e 65 74 } 		$a_00_2 = {72 65 63 5f 73 63 72 69 70 74 2e 73 68 } 		$a_00_3 = {41 64 73 50 72 6f 78 79 45 6e 67 69 6e 65 3a 3a 69 6e 69 74 28 29 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}