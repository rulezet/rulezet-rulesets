rule Trojan_AndroidOS_Guerrilla_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Guerrilla.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {6e 75 6d 62 65 72 49 6e 43 6f 6e 74 72 61 63 74 } 		$a_00_1 = {67 65 74 53 6d 73 43 6f 75 6e 74 } 		$a_00_2 = {63 61 6e 4b 69 6c 6c 50 68 6f 6e 65 50 72 6f 63 65 73 73 } 		$a_00_3 = {53 6d 73 48 6f 6f 6b } 		$a_00_4 = {64 65 6c 53 65 6e 64 4d 73 67 } 		$a_00_5 = {73 6d 5f 73 70 5f 77 73 5f 75 72 6c } 		$a_00_6 = {68 6f 6f 6b 50 68 6f 6e 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}