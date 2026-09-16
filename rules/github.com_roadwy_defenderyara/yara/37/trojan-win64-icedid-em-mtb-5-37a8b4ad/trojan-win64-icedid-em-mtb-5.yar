rule Trojan_Win64_IcedID_EM_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 4f 34 44 54 36 6a 48 54 55 } 		$a_01_1 = {4e 6f 36 4d 4c 39 6a 4f 49 } 		$a_01_2 = {52 58 56 6c 30 36 58 71 73 } 		$a_01_3 = {66 50 33 57 36 35 72 79 } 		$a_01_4 = {68 61 73 64 6e 75 68 61 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}