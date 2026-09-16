rule Trojan_BAT_Formbook_NZB_MTB_2{
	meta:
		description = "Trojan:BAT/Formbook.NZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 1f 25 9d 6f ?? 00 00 0a 13 04 38 ?? ?? ?? ?? 00 02 } 		$a_81_1 = {4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 } 		$a_81_2 = {33 39 39 30 35 66 63 37 35 62 33 33 } 	condition:
		((#a_03_0  & 1)*3+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=5
 
}