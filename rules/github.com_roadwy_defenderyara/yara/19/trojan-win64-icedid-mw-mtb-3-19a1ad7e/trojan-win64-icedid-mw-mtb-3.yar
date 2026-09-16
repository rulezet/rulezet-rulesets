rule Trojan_Win64_IcedID_MW_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_1 = {54 41 62 5a 39 36 2e 64 6c 6c } 		$a_01_2 = {41 6e 56 6e 73 74 36 } 		$a_01_3 = {46 65 5a 31 71 48 51 38 54 37 } 		$a_01_4 = {67 33 68 78 62 6c 41 4e 63 37 4b } 		$a_01_5 = {7a 4e 4d 35 6c 57 73 37 4c 51 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}