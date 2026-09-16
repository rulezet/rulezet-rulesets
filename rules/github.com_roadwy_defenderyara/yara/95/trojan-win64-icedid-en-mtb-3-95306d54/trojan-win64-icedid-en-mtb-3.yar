rule Trojan_Win64_IcedID_EN_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 53 36 55 4d 46 34 73 4a 51 } 		$a_01_1 = {56 70 65 72 46 67 37 4c 33 } 		$a_01_2 = {64 54 51 5a 6a 67 69 4b 6a } 		$a_01_3 = {66 79 77 54 61 77 76 78 45 41 } 		$a_01_4 = {67 79 68 6a 75 68 79 61 73 62 68 6a 6b 61 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}