rule Adware_MacOS_Pirrit_B{
	meta:
		description = "Adware:MacOS/Pirrit.B,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 73 6c 65 65 70 46 6f 72 54 69 6d 65 49 6e 74 65 72 76 61 6c 3a } 		$a_01_1 = {25 6a 39 7d 6f 51 } 		$a_01_2 = {4d 32 3c 50 77 63 3a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}