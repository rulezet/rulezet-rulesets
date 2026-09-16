rule Trojan_BAT_Jalapeno_PGJ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.PGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 02 7b 05 00 00 04 08 9a 7d 06 00 00 04 02 03 28 ?? 00 00 06 0d 02 7b 09 00 00 04 09 72 01 00 00 70 6f ?? 00 00 0a 0b 07 72 01 00 00 70 28 ?? 00 00 0a 2c 07 07 28 ?? 00 00 2b 2a 08 17 58 0c 08 02 7b 05 00 00 04 8e 69 32 b5 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}