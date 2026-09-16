rule Trojan_AndroidOS_Spynote_H{
	meta:
		description = "Trojan:AndroidOS/Spynote.H,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {52 65 67 6e 65 77 } 		$a_00_1 = {52 65 71 69 65 73 74 65 4e 65 77 4a 6f 62 } 		$a_00_2 = {41 63 74 69 76 53 65 6e 64 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}