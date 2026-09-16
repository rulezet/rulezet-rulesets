rule Trojan_BAT_FormBook_AFB_MTB_5{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 10 62 12 00 28 ?? 00 00 0a 1e 62 60 12 00 28 ?? 00 00 0a 60 0c 03 08 1f 10 63 20 ff 00 00 00 5f d2 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}