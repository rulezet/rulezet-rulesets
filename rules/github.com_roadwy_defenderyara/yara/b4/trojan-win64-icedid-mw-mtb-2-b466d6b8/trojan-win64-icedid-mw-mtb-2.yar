rule Trojan_Win64_IcedID_MW_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 4f 62 6a 65 63 74 } 		$a_01_1 = {71 33 6d 67 75 47 35 56 2e 64 6c 6c } 		$a_01_2 = {44 47 6c 44 39 46 37 74 68 45 } 		$a_01_3 = {49 72 50 55 71 4e 35 73 36 46 56 } 		$a_01_4 = {65 51 6a 4b 75 6a 68 } 		$a_01_5 = {6c 4e 67 74 6e 4a } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}