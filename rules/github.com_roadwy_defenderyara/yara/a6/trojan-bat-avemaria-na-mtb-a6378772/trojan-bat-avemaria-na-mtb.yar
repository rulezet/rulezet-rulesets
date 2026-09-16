rule Trojan_BAT_AveMaria_NA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 8b 00 00 0a 6f 3b 00 00 06 0c 28 08 00 00 06 6f 85 00 00 0a 09 72 19 01 00 70 06 18 9a 28 8c 00 00 0a 07 16 6f 8d 00 00 0a 00 28 08 00 00 06 6f 85 00 00 0a } 		$a_01_1 = {13 04 00 28 8f 00 00 0a 6f 90 00 00 0a 00 28 38 00 00 0a } 		$a_01_2 = {73 74 75 62 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}