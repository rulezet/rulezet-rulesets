rule Trojan_BAT_AsyncRAT_NA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7d 01 00 00 04 08 17 58 0c 2b 09 06 03 08 94 6f ?? 00 00 0a 08 17 } 		$a_03_1 = {28 01 00 00 2b 28 ?? 00 00 2b 0a 1a 06 6f ?? 00 00 0a 59 0b } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}