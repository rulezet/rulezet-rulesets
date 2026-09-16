rule Trojan_AndroidOS_Piom_V_2{
	meta:
		description = "Trojan:AndroidOS/Piom.V,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 65 70 6f 72 74 41 6c 6c 50 72 6f 70 65 72 74 69 65 73 4d 65 73 73 61 67 65 } 		$a_01_1 = {41 43 54 49 4f 4e 5f 4c 49 53 54 45 4e 45 52 5f 55 53 45 52 5f 52 45 4d 4f 54 45 5f 43 4f 4e 54 52 4f 4c } 		$a_01_2 = {45 58 54 52 41 4c 5f 52 45 53 54 41 52 54 5f 57 4f 52 4b 53 45 52 56 49 43 45 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}