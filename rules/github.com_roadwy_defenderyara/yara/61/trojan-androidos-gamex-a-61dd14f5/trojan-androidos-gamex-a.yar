rule Trojan_AndroidOS_Gamex_A{
	meta:
		description = "Trojan:AndroidOS/Gamex.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 75 69 6c 64 43 6f 6e 66 69 67 2e 6a 61 76 61 } 		$a_01_1 = {54 61 72 67 65 74 41 70 69 2e 6a 61 76 61 } 		$a_01_2 = {69 6e 70 75 74 65 78 2f 69 6e 64 65 78 2e 70 68 70 3f 73 3d 2f 49 6e 74 65 72 66 61 63 65 2f 6e 65 69 69 6e 74 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}