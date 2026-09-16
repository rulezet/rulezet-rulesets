rule Trojan_AndroidOS_Soceng_PT{
	meta:
		description = "Trojan:AndroidOS/Soceng.PT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 79 53 65 72 76 69 63 65 73 24 41 73 79 6e 63 5f 73 65 6e 64 53 4d 53 } 		$a_01_1 = {55 4e 49 4e 53 54 41 4c 4c 5f 50 41 43 4b 41 47 45 5f 45 58 49 53 54 45 44 5f 50 57 44 } 		$a_01_2 = {61 64 64 53 4d 53 49 6e 74 6f 49 6e 62 6f 78 } 		$a_01_3 = {64 65 61 63 74 69 76 61 74 65 44 65 76 69 63 65 41 64 6d 69 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}