rule Trojan_BAT_AveMaria_MA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {0c 08 16 08 8e 69 28 17 00 00 0a 08 0d de 0a 07 2c 06 06 28 18 00 00 0a dc } 		$a_01_1 = {9e 07 06 11 05 94 58 0b 11 05 17 58 13 05 11 05 1f 0a 32 c0 } 		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*2) >=12
 
}