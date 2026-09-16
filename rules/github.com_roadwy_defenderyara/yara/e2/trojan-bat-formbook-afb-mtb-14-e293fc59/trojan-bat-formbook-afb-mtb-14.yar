rule Trojan_BAT_FormBook_AFB_MTB_14{
	meta:
		description = "Trojan:BAT/FormBook.AFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 2b 3a 06 09 5d 13 05 06 17 58 09 5d 13 0a 07 11 0a 91 ?? ?? ?? ?? ?? 58 13 0b 07 11 05 91 13 0c 07 11 05 11 0c 11 06 06 1f 16 5d 91 61 11 0b 59 ?? ?? ?? ?? ?? 5d d2 9c 06 17 58 0a 06 09 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}