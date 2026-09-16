rule Trojan_AndroidOS_Spynote_E_2{
	meta:
		description = "Trojan:AndroidOS/Spynote.E,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {74 68 69 73 20 61 70 70 20 64 6f 65 73 20 6e 6f 74 20 73 75 70 70 6f 72 74 20 65 6d 75 6c 61 74 6f 72 20 64 65 76 69 63 65 73 } 		$a_01_1 = {74 6f 20 41 6c 6c 6f 77 20 61 70 70 2c 20 64 69 73 61 62 6c 65 20 66 69 72 65 77 61 6c 6c 20 66 69 72 73 74 2e } 		$a_01_2 = {43 6c 69 63 6b 3a 20 5b 44 65 6c 65 74 65 5d } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}