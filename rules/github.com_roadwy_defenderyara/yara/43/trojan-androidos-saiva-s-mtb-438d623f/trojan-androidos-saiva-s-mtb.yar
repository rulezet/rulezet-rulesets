rule Trojan_AndroidOS_Saiva_S_MTB{
	meta:
		description = "Trojan:AndroidOS/Saiva.S!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 64 6f 77 6e 6c 6f 61 64 65 72 2f 41 70 70 44 6f 77 6e 6c 6f 61 64 65 72 41 63 74 69 76 69 74 79 } 		$a_00_1 = {2f 64 6f 77 6e 6c 6f 61 64 65 72 2f 53 6d 73 52 65 63 65 69 76 65 72 } 		$a_00_2 = {2f 67 65 74 54 61 73 6b 2e 70 68 70 } 		$a_00_3 = {26 62 61 6c 61 6e 63 65 } 		$a_00_4 = {4c 61 73 74 20 62 6f 6f 6b 6d 61 72 6b } 		$a_00_5 = {62 6c 61 63 6b 4e 75 6d 62 65 72 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}