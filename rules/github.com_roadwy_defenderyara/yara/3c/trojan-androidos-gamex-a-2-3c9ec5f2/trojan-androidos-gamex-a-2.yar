rule Trojan_AndroidOS_Gamex_A_2{
	meta:
		description = "Trojan:AndroidOS/Gamex.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 68 6d 6f 64 20 36 34 34 20 2f 73 79 73 74 65 6d 2f 61 70 70 2f 43 6f 6d 41 6e 64 72 6f 69 64 53 65 74 74 69 6e 67 2e 61 70 6b } 		$a_01_1 = {67 61 6d 65 78 2f 69 6e 73 65 74 2f 42 75 69 6c 64 43 6f 6e 66 69 67 } 		$a_01_2 = {6c 6f 67 6f 73 2e 70 6e 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}