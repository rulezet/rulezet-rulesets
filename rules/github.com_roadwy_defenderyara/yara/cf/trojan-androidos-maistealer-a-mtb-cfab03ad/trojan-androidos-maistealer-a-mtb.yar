rule Trojan_AndroidOS_Maistealer_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Maistealer.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 75 62 65 66 6c 69 63 5f 65 73 5f 63 6f 6d 41 63 74 69 76 69 74 79 } 		$a_01_1 = {63 6f 6d 2f 74 75 62 65 66 6c 69 63 5f 65 73 2f 63 6f 6d } 		$a_01_2 = {68 61 73 53 65 6e 74 46 69 72 73 74 53 4d 53 } 		$a_01_3 = {53 6d 73 52 65 63 65 69 76 65 72 48 65 6c 70 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}