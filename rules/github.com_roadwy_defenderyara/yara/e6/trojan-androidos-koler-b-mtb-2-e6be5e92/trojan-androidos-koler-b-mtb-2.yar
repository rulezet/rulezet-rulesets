rule Trojan_AndroidOS_Koler_B_MTB_2{
	meta:
		description = "Trojan:AndroidOS/Koler.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 66 74 75 62 65 2e 6f 72 67 2f 73 65 6e 64 2e 70 68 70 } 		$a_01_1 = {72 65 73 70 6f 6e 73 65 5f 73 65 72 76 } 		$a_01_2 = {6c 6f 63 6b 53 63 72 65 65 6e 52 65 65 69 76 65 72 } 		$a_01_3 = {63 6f 6d 2f 6c 6f 63 6b 2f 61 70 70 2f 53 74 61 72 74 4f 76 56 69 65 77 } 		$a_01_4 = {73 65 6e 64 65 72 5f 70 69 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}