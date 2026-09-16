rule Trojan_BAT_Heracles_NH_MTB_5{
	meta:
		description = "Trojan:BAT/Heracles.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {2b 1f 09 11 07 9a 08 28 24 00 00 0a 2c 0d 09 11 07 17 58 9a 13 04 16 } 		$a_81_1 = {61 73 70 6e 65 74 5f 77 70 2e 65 78 65 } 		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } 		$a_81_3 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } 	condition:
		((#a_01_0  & 1)*7+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=10
 
}