rule Trojan_AndroidOS_Piom_A{
	meta:
		description = "Trojan:AndroidOS/Piom.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 2e 6a 73 6f 6e } 		$a_01_1 = {73 74 61 72 74 2e 70 6e 67 } 		$a_01_2 = {48 75 61 6e 79 69 6e 41 63 74 69 76 69 74 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}