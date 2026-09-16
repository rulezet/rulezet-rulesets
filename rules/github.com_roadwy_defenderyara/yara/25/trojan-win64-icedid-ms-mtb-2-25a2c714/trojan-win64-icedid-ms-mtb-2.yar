rule Trojan_Win64_IcedID_MS_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {36 70 4d 6a 76 72 2e 64 6c 6c } 		$a_01_1 = {75 69 6a 6e 73 64 76 66 62 67 73 7a } 		$a_01_2 = {58 6a 46 52 69 33 65 4c 66 72 46 } 		$a_01_3 = {45 42 6a 57 61 77 } 		$a_01_4 = {56 57 44 52 34 37 69 79 75 } 		$a_01_5 = {6d 55 4c 30 5a 48 6c 6f 55 61 4a } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}