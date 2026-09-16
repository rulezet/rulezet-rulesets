rule Trojan_AndroidOS_Spynote_PH{
	meta:
		description = "Trojan:AndroidOS/Spynote.PH,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 63 65 72 63 72 65 61 74 69 6e 67 6a 35 39 37 32 37 } 		$a_01_1 = {63 76 73 61 63 65 72 63 72 65 61 74 69 6e 67 6a 35 39 37 32 32 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}