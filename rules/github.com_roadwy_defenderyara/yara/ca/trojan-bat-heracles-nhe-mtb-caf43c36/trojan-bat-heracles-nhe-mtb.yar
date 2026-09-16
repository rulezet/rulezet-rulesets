rule Trojan_BAT_Heracles_NHE_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 07 19 5a 58 47 09 16 94 04 59 fe 04 16 fe 01 11 06 11 07 19 5a 58 47 09 16 94 04 58 } 		$a_01_1 = {5a 61 68 75 72 61 43 48 2e 55 74 69 6c 73 2e 57 69 6e 53 74 72 75 63 74 73 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}