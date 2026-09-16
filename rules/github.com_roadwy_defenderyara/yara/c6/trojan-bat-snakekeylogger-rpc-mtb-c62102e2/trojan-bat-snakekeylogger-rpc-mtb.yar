rule Trojan_BAT_SnakeKeylogger_RPC_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2c 03 17 2b 03 16 2b 00 2d 03 26 2b 07 28 1a 00 00 0a 2b 00 2a 90 09 06 00 20 20 4e 00 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}