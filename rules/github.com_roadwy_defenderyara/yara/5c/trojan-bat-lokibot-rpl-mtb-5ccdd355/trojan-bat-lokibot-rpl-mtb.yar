rule Trojan_BAT_LokiBot_RPL_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 1b 59 1c 58 0d 09 17 32 ce 06 17 58 0a 08 1a 59 1b 58 0c 08 20 00 d8 00 00 32 b8 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}