rule Trojan_BAT_FormBook_AFB_MTB_16{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 91 1d 59 1f 09 59 d2 0b 07 06 02 07 9c 2a } 		$a_03_1 = {17 59 0a 2b 1e 02 03 06 6f ?? 00 00 0a 93 0b 02 03 06 6f ?? 00 00 0a 02 06 93 9d 02 06 07 9d 06 17 59 0a 06 16 2f de } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}