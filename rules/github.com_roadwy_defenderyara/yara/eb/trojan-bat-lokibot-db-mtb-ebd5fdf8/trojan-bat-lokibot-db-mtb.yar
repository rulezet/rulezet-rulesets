rule Trojan_BAT_LokiBot_DB_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 14 07 06 08 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 58 0c 08 20 00 38 01 00 32 e4 } 		$a_01_1 = {4d 61 67 6e 61 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 		$a_01_2 = {53 70 6c 69 74 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}