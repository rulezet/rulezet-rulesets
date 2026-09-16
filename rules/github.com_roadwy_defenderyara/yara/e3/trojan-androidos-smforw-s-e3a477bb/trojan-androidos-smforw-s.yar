rule Trojan_AndroidOS_Smforw_S{
	meta:
		description = "Trojan:AndroidOS/Smforw.S,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 65 63 72 65 74 54 61 6c 6b 41 70 70 } 		$a_01_1 = {72 65 61 64 79 20 74 6f 20 72 65 63 65 69 76 65 20 73 6d 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}