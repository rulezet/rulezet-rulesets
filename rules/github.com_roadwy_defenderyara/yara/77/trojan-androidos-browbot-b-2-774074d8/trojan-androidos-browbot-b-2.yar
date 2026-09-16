rule Trojan_AndroidOS_BrowBot_B_2{
	meta:
		description = "Trojan:AndroidOS/BrowBot.B,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 61 38 70 2e 6e 65 74 2f 74 71 66 58 44 6e } 		$a_01_1 = {24 44 65 76 69 63 65 4d 6f 64 65 6c 5f 31 36 } 		$a_01_2 = {73 65 6e 64 65 72 70 68 6f 6e 65 5f 31 36 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}