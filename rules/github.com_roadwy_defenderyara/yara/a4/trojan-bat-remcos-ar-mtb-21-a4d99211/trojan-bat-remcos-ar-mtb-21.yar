rule Trojan_BAT_Remcos_AR_MTB_21{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 19 00 02 7b af 00 00 04 06 8f 79 00 00 01 25 47 03 58 d2 52 00 06 17 58 d2 0a 06 1f 0a fe 04 0b 07 2d de } 		$a_01_1 = {65 00 63 00 6e 00 61 00 74 00 73 00 6e 00 49 00 65 00 74 00 61 00 65 00 72 00 43 00 } 		$a_01_2 = {53 74 72 52 65 76 65 72 73 65 } 		$a_01_3 = {6f 00 73 00 75 00 6b 00 70 00 73 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}