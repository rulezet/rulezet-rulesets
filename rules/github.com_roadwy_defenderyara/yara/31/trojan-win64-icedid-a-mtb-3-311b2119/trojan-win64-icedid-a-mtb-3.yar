rule Trojan_Win64_IcedID_A_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4e 71 70 33 33 74 2e 64 6c 6c } 		$a_01_1 = {48 61 79 75 67 66 6e 61 73 75 62 79 66 68 68 6a 73 73 } 		$a_01_2 = {58 4b 59 39 53 69 47 74 78 51 5a 4d 69 4f 34 } 		$a_01_3 = {63 69 32 6a 44 49 63 5a 75 6a 4e 37 6b } 		$a_01_4 = {68 4f 42 4c 46 7a 6c 43 4f 66 58 76 56 38 56 66 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}