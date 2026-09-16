rule Trojan_AndroidOS_Hqwar_J_MTB{
	meta:
		description = "Trojan:AndroidOS/Hqwar.J!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {69 6e 6a 5f 64 6e 6c 61 64 65 72 } 		$a_00_1 = {66 61 6b 6e 6f 74 69 61 63 74 69 76 69 74 79 } 		$a_00_2 = {66 6f 72 63 5f 61 63 74 69 76 61 74 65 61 63 63 } 		$a_00_3 = {69 63 65 2f 73 6d 73 70 6c 75 73 } 		$a_00_4 = {2f 6e 62 36 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}