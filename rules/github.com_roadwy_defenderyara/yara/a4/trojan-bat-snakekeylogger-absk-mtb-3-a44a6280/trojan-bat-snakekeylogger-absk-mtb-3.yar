rule Trojan_BAT_SnakeKeylogger_ABSK_MTB_3{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.ABSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 08 06 6f ?? 00 00 0a 13 0c 04 03 6f ?? 00 00 0a 59 0d } 		$a_03_1 = {07 1f 63 58 0b 03 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 09 17 59 25 0d 16 fe 02 16 fe 01 2d 3c 03 12 0c } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}