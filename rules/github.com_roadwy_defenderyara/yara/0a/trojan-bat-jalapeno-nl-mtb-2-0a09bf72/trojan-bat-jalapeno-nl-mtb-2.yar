rule Trojan_BAT_Jalapeno_NL_MTB_2{
	meta:
		description = "Trojan:BAT/Jalapeno.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 7b bc 01 00 04 1c 8d 78 00 00 01 25 16 02 7c b8 00 00 04 28 57 00 00 0a a2 25 17 72 95 32 00 70 a2 25 18 02 7c b6 00 00 04 28 57 00 00 0a a2 25 19 72 a7 32 00 70 a2 25 1a 02 7c b7 00 00 04 28 57 00 00 0a a2 25 1b 72 ab 32 00 70 a2 28 5e 00 00 0a 6f 2a 00 00 0a } 		$a_01_1 = {64 00 6f 00 6e 00 65 00 5f 00 64 00 72 00 6f 00 70 00 65 00 64 00 } 		$a_01_2 = {65 44 62 61 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}