rule Trojan_BAT_LokiBot_RPZ_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 1f 16 5d 91 61 28 ab 00 00 0a 02 07 17 58 02 8e 69 5d 91 28 ac 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 07 15 58 0b 07 16 2f c2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}