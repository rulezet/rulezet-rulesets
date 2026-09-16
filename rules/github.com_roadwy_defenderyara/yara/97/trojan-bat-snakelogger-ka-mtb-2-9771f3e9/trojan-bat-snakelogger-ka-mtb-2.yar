rule Trojan_BAT_SnakeLogger_KA_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeLogger.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 38 00 34 00 2e 00 35 00 34 00 2e 00 35 00 30 00 2e 00 33 00 31 00 2f 00 44 00 } 		$a_01_1 = {42 4e 42 55 4e 37 36 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}