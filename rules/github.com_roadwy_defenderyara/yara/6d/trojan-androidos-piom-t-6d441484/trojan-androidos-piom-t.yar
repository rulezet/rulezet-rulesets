rule Trojan_AndroidOS_Piom_T{
	meta:
		description = "Trojan:AndroidOS/Piom.T,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {79 29 2d 23 73 75 73 70 65 63 74 28 79 29 2d 23 5f 6e 75 6d 62 28 79 29 2d 23 65 72 73 } 		$a_01_1 = {28 79 29 2d 23 75 72 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}