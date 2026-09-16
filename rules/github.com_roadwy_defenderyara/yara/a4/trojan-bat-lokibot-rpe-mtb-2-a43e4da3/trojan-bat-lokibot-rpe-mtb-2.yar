rule Trojan_BAT_LokiBot_RPE_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 06 07 06 6f e6 00 00 0a 5d 6f b0 01 00 0a 28 59 03 00 06 07 91 73 80 02 00 0a 0c 28 59 03 00 06 07 08 6f 81 02 00 0a 08 6f 82 02 00 0a 61 28 83 02 00 0a 9c 00 07 17 58 0b 07 28 59 03 00 06 8e 69 fe 04 0d 09 2d b8 } 		$a_01_1 = {53 00 53 00 51 00 4a 00 52 00 53 00 57 00 59 00 49 00 48 00 54 00 57 00 51 00 41 00 58 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}