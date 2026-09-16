rule Adware_MacOS_Pirrit_C{
	meta:
		description = "Adware:MacOS/Pirrit.C,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {80 35 33 53 02 00 b1 80 35 2d 53 02 00 f7 80 35 27 53 02 00 1b } 		$a_01_1 = {3d 5f 74 57 2c 74 35 3d } 		$a_01_2 = {7d 6d 31 65 6a 5b 72 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}