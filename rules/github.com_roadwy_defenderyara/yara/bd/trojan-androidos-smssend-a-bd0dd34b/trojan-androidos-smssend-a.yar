rule Trojan_AndroidOS_SmsSend_A{
	meta:
		description = "Trojan:AndroidOS/SmsSend.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 52 45 4e 41 20 45 58 43 49 54 45 } 		$a_01_1 = {47 41 4c 20 43 41 4e 54 49 4b } 		$a_01_2 = {50 70 61 67 65 72 6f 6d 6f } 		$a_01_3 = {4f 6e 74 6b 65 6e 6e 69 6e 67 44 69 73 } 		$a_01_4 = {4f 4e 20 47 41 4d 45 20 4b 49 53 53 } 		$a_01_5 = {47 49 52 4c 20 43 41 4e 54 49 4b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}