rule Trojan_BAT_FormBook_AKB_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 27 00 07 11 1d 11 1e 11 24 94 1f 1f 5f 63 20 ff 00 00 00 5f d2 6f ?? ?? ?? 0a 00 00 11 24 17 58 13 24 11 1f 17 59 13 1f 11 24 19 2f 07 11 1f 16 fe 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}