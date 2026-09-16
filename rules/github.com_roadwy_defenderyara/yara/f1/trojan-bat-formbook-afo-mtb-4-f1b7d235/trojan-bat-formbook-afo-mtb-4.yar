rule Trojan_BAT_FormBook_AFO_MTB_4{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 2a 2b 2f 16 2d f2 2b 31 72 ?? ?? ?? 70 2b 2d 16 2c 31 26 26 2b 34 2b 35 06 16 06 8e 69 6f ?? 00 00 0a 0c 1c 2c d2 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}