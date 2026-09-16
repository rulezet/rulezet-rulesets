rule Trojan_Win64_IcedID_EM_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {58 35 6a 68 68 34 57 71 } 		$a_01_1 = {65 66 35 71 54 71 } 		$a_01_2 = {68 61 73 64 6e 75 68 61 73 } 		$a_01_3 = {6f 59 56 45 54 72 } 		$a_01_4 = {72 66 6f 45 71 48 43 4e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}