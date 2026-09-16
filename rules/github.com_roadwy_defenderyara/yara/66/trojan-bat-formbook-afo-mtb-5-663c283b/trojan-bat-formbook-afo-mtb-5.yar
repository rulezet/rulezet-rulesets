rule Trojan_BAT_FormBook_AFO_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 59 9a 0c 08 28 ?? 00 00 0a 16 fe 01 13 06 11 06 2d 03 00 2b 2f 00 06 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 00 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}