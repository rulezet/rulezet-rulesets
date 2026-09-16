rule Trojan_Win64_IcedID_EM_MTB_6{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 49 76 61 6b 4c 78 61 37 } 		$a_01_1 = {55 59 74 62 6b 41 6a 77 } 		$a_01_2 = {55 63 53 74 79 68 53 } 		$a_01_3 = {61 67 6a 68 73 61 68 6a 61 73 6b 73 64 } 		$a_01_4 = {68 51 36 4a 38 6d 69 49 46 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}