rule PWS_BAT_Stimilini_C{
	meta:
		description = "PWS:BAT/Stimilini.C,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 67 65 74 5f 75 6d 71 75 69 64 00 } 		$a_01_1 = {00 73 65 74 5f 75 6d 71 75 69 64 00 } 		$a_01_2 = {00 67 65 74 5f 73 74 65 61 6d 49 44 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}