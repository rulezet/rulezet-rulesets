rule Backdoor_Linux_Flashback_E{
	meta:
		description = "Backdoor:Linux/Flashback.E,SIGNATURE_TYPE_MACHOHSTR_EXT,0f 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 } 		$a_01_1 = {75 70 64 61 74 65 3f 69 66 3d 25 26 66 75 3d 25 75 } 		$a_01_2 = {6c 61 75 6e 63 68 63 74 6c 20 6c 6f 61 64 } 		$a_01_3 = {7c 6f 6c 64 75 70 64 61 74 65 } 		$a_01_4 = {7c 3c 67 3e 7c } 		$a_01_5 = {73 75 64 6f 20 2d 75 } 		$a_01_6 = {36 36 34 39 32 33 34 3b 38 35 37 35 33 34 33 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*10) >=14
 
}