rule Trojan_Win64_IcedID_EN_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 61 69 6e 77 50 56 66 43 45 } 		$a_01_1 = {56 49 4c 4f 4b 6e 49 70 76 4d 74 } 		$a_01_2 = {56 62 68 6a 66 73 67 75 61 73 6a 66 6e 61 73 66 } 		$a_01_3 = {58 76 6b 43 43 52 62 } 		$a_01_4 = {5a 42 50 41 63 5a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}