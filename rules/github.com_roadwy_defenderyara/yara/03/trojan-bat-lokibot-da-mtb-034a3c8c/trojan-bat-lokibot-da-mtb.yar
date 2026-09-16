rule Trojan_BAT_LokiBot_DA_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 08 9a 28 ?? ?? ?? 0a 0d 7e ?? ?? ?? 04 09 6f ?? ?? ?? 0a 00 00 08 17 d6 0c 08 07 8e 69 fe 04 13 04 11 04 2d da } 		$a_81_1 = {53 68 6f 70 5f 4d 61 6e 61 67 65 72 } 		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}