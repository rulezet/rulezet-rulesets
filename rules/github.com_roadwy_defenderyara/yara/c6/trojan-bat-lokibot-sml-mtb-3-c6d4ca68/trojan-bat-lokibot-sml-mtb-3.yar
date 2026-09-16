rule Trojan_BAT_LokiBot_SML_MTB_3{
	meta:
		description = "Trojan:BAT/LokiBot.SML!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 09 91 11 06 61 11 08 59 20 00 02 00 00 58 13 0a 02 11 0a 28 55 00 00 06 13 0b 02 11 0b 28 56 00 00 06 13 0c 02 11 0c 28 57 00 00 06 13 0d 02 11 0d 28 58 00 00 06 13 0e 07 11 05 11 0e d2 9c 11 05 17 58 13 05 11 05 08 32 88 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}