rule Trojan_BAT_FormBook_AFO_MTB_14{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 0e 02 03 06 04 05 28 ?? 00 00 06 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 0b 04 6f ?? 00 00 0a 05 fe 04 2b 01 16 0b 07 2d d9 } 		$a_03_1 = {02 03 04 6f ?? 00 00 0a 0a 0e 04 05 6f ?? 00 00 0a 59 0b 06 07 05 28 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}