rule Trojan_AndroidOS_SmsBot_A{
	meta:
		description = "Trojan:AndroidOS/SmsBot.A,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {52 65 6d 6f 76 65 41 6c 6c 53 6d 73 41 6e 73 77 65 72 73 } 		$a_00_1 = {73 74 61 72 74 42 61 63 6b 67 72 6f 75 6e 64 53 6d 73 28 29 } 		$a_00_2 = {4c 64 65 6c 65 74 65 2f 6f 66 66 2f 41 64 6d 69 6e 52 65 63 65 69 76 65 72 3b } 		$a_00_3 = {53 49 50 4d 4c 45 5f 50 48 4f 4e 45 5f 41 4e 44 5f 54 45 58 54 } 		$a_00_4 = {69 73 46 69 73 72 74 28 29 3a 20 74 72 75 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}