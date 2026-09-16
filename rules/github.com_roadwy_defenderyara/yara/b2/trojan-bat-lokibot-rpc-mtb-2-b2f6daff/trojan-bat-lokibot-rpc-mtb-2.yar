rule Trojan_BAT_LokiBot_RPC_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 06 07 06 6f 25 00 00 0a 5d 6f 26 00 00 0a 28 08 00 00 06 07 91 73 27 00 00 0a 0c 28 08 00 00 06 07 08 6f 28 00 00 0a 08 6f 29 00 00 0a 61 28 2a 00 00 0a 9c 00 07 17 58 0b 07 28 08 00 00 06 8e 69 fe 04 0d 09 2d b8 } 		$a_01_1 = {32 00 34 00 59 00 38 00 47 00 59 00 44 00 51 00 32 00 4a 00 36 00 56 00 54 00 4a 00 42 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}