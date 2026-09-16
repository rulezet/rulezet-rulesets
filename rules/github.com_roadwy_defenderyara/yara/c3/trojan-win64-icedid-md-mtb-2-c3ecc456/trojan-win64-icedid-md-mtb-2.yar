rule Trojan_Win64_IcedID_MD_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_1 = {41 6b 71 45 57 2e 64 6c 6c } 		$a_01_2 = {4a 72 69 61 41 44 76 50 37 64 4c } 		$a_01_3 = {5a 47 6e 55 32 42 71 42 67 70 70 } 		$a_01_4 = {68 4f 6e 34 32 65 62 62 33 } 		$a_01_5 = {73 30 4a 72 70 79 64 54 61 71 70 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}