rule Trojan_AndroidOS_Piom_A_2{
	meta:
		description = "Trojan:AndroidOS/Piom.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {49 6e 6a 65 63 74 69 6f 6e 20 69 73 20 73 75 63 63 65 73 73 66 75 6c } 		$a_00_1 = {66 67 64 66 76 63 76 2e 6f 72 67 } 		$a_00_2 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 62 6f 74 2f 43 6f 6d 6d 61 6e 64 4c 69 73 74 65 6e 65 72 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}