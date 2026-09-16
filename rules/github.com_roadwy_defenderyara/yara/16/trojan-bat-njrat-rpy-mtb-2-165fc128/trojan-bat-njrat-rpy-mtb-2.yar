rule Trojan_BAT_Njrat_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/Njrat.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {14 0a 73 20 00 00 0a 0b 07 28 21 00 00 0a 02 6f 22 00 00 0a 6f 23 00 00 0a 0a 07 6f 24 00 00 0a 06 2a } 		$a_01_1 = {63 6c 61 73 68 20 6e 6a 72 61 74 } 		$a_01_2 = {52 65 70 6c 61 63 65 } 		$a_01_3 = {54 6f 53 74 72 69 6e 67 } 		$a_01_4 = {53 6c 65 65 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}