rule Trojan_BAT_FormBook_AFO_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 1a 07 09 06 09 91 08 09 08 6f ?? 01 00 0a 5d 6f ?? 01 00 0a 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}