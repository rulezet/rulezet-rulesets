rule Trojan_AndroidOS_BrowBot_B{
	meta:
		description = "Trojan:AndroidOS/BrowBot.B,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 70 69 6e 65 74 63 6f 6d 2e 63 6f 6d 2f 64 61 74 61 } 		$a_01_1 = {61 38 70 2e 6e 65 74 2f 74 71 66 58 44 6e } 		$a_01_2 = {73 6f 75 72 63 65 7a 5f 31 35 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}