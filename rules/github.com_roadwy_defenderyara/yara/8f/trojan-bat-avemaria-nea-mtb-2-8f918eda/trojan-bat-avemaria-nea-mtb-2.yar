rule Trojan_BAT_AveMaria_NEA_MTB_2{
	meta:
		description = "Trojan:BAT/AveMaria.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 09 8f 65 00 00 01 72 94 0a 00 70 28 6b 00 00 0a 6f 6c 00 00 0a 26 00 09 17 58 0d 09 07 8e 69 fe 04 13 04 11 04 2d d6 } 		$a_01_1 = {35 00 58 00 54 00 4f 00 44 00 35 00 47 00 34 00 51 00 35 00 34 00 47 00 5a 00 38 00 35 00 37 00 42 00 53 00 43 00 38 00 37 00 34 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}