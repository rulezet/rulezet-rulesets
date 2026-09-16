rule Trojan_BAT_LokiBot_RPC_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 16 08 02 00 0c 2b 13 00 06 08 20 00 01 00 00 28 07 00 00 06 0a 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}