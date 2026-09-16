rule Trojan_Win64_IcedID_EM_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 6a 68 61 73 79 75 69 6a 6b 61 73 } 		$a_01_1 = {42 6e 6d 72 38 34 51 65 79 } 		$a_01_2 = {43 53 45 4e 56 78 4a } 		$a_01_3 = {45 68 73 54 65 44 30 73 32 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}