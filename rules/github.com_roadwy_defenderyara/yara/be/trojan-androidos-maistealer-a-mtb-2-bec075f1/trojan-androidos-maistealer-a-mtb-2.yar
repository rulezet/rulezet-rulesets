rule Trojan_AndroidOS_Maistealer_A_MTB_2{
	meta:
		description = "Trojan:AndroidOS/Maistealer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 61 69 6c 61 64 64 72 65 73 73 20 67 65 74 21 } 		$a_00_1 = {73 74 72 4d 61 69 6c 4c 69 73 74 } 		$a_00_2 = {61 64 64 72 65 73 73 63 61 70 2f 6c 69 73 74 2e 6c 6f 67 } 		$a_00_3 = {63 6f 6e 73 75 6d 65 43 6f 6e 74 65 6e 74 } 		$a_00_4 = {70 6f 73 74 4d 61 69 6c 4c 69 73 74 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}