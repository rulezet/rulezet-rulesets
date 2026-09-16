rule Trojan_Win64_IcedID_EN_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 63 65 6a 73 6f } 		$a_01_1 = {73 49 77 59 6a 67 4e 42 59 } 		$a_01_2 = {76 77 63 4b 70 42 5a 57 41 75 50 5a 74 6f 66 47 } 		$a_01_3 = {77 43 55 78 56 72 58 54 73 4d 47 56 78 42 47 72 } 		$a_01_4 = {7a 75 62 69 74 6a 6b 66 6e 61 73 79 66 75 6a 61 73 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}