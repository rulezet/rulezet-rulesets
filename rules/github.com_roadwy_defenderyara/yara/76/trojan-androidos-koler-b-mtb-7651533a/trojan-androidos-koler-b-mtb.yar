rule Trojan_AndroidOS_Koler_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Koler.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 65 7a 75 6c 74 73 74 72 6f 6b 61 } 		$a_01_1 = {70 69 6e 69 6e 70 75 74 } 		$a_01_2 = {63 61 72 64 69 6e 70 75 74 } 		$a_01_3 = {61 63 63 61 75 6e 74 73 } 		$a_01_4 = {75 73 65 72 44 65 74 61 69 6c 73 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}