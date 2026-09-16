rule Trojan_BAT_FormBook_SKC_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.SKC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 30 00 00 0a 13 05 04 03 6f 2f 00 00 0a 59 13 06 03 12 05 28 31 00 00 0a 6f 32 00 00 0a 11 06 17 59 25 13 06 16 31 32 03 12 05 28 33 00 00 0a 6f 32 00 00 0a 11 06 17 59 25 13 06 16 31 1b 03 12 05 28 34 00 00 0a 6f 32 00 00 0a 07 17 58 0b 2b 90 06 17 58 0a 16 0b 2b 88 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}