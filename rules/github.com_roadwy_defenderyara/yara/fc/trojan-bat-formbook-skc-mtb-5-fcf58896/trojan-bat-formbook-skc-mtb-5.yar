rule Trojan_BAT_FormBook_SKC_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.SKC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 11 0b 17 58 1f 25 5a 11 0e 17 58 1f 65 5a 61 07 61 13 0f 11 0f 11 0d 23 00 00 00 00 00 40 8f 40 5a 69 61 13 0f 02 11 0b 11 0e 6f 1a 00 00 0a 13 10 04 03 6f 1b 00 00 0a 59 } 		$a_01_1 = {00 11 12 20 cb 03 00 00 5a 11 0f 20 f5 03 00 00 5a 61 20 ff 03 00 00 5f 13 13 06 11 13 1b 63 94 17 11 13 1f 1f 5f 1f 1f 5f 62 5f 16 fe 03 13 14 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}