rule Trojan_BAT_FormBook_AFO_MTB_6{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 16 0d 2b 22 07 09 18 6f 1e 00 00 0a 1f 10 28 b3 00 00 0a 13 04 11 04 16 32 08 08 11 04 6f 3c 00 00 0a 09 18 58 0d 09 07 6f 21 00 00 0a 32 d5 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}