rule Trojan_BAT_FormBook_AFR_MTB{
	meta:
		description = "Trojan:BAT/FormBook.AFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 6a 13 09 2b 53 00 11 09 1f 16 6a 5d 13 0a 07 11 09 07 8e 69 6a 5d d4 07 11 09 07 8e 69 6a 5d d4 91 08 11 0a 69 6f ?? 01 00 0a 61 07 11 09 17 6a 58 07 8e 69 6a 5d d4 91 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}