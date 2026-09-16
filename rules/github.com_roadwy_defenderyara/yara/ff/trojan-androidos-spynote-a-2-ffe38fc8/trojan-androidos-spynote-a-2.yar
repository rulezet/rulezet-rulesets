rule Trojan_AndroidOS_Spynote_A_2{
	meta:
		description = "Trojan:AndroidOS/Spynote.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 50 49 5f 53 45 54 5f 41 43 43 4f 55 4e 54 5f 4e 49 43 4b 4e 41 4d 45 } 		$a_00_1 = {61 70 70 73 69 6e 66 6f 5f 66 75 6c 6c 2f } 		$a_00_2 = {70 65 72 6d 73 5f 6c 69 73 74 5f 66 75 6c 6c 2f } 		$a_00_3 = {41 50 49 5f 53 54 41 52 54 5f 50 4f 49 4e 54 5f 44 4f 4e 41 54 49 4f 4e } 		$a_00_4 = {6e 65 74 2f 61 78 65 6c 2f 61 70 70 2f 73 65 72 73 65 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}