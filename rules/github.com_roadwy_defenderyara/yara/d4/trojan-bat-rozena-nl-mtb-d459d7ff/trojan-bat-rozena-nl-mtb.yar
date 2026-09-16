rule Trojan_BAT_Rozena_NL_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 14 00 00 0a 16 11 04 7e 14 00 00 0a 16 7e 14 00 00 0a 28 02 00 00 06 15 } 		$a_01_1 = {0a 20 d0 07 00 00 28 04 00 00 06 28 10 00 00 0a 13 05 12 05 06 28 11 00 00 0a 13 06 12 06 28 12 00 00 0a } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}