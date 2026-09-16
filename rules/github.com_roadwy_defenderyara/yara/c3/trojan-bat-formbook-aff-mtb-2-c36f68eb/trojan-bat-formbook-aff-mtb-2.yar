rule Trojan_BAT_FormBook_AFF_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.AFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 21 12 0a 28 ?? ?? ?? 0a 13 0b 2b 16 12 0a 28 ?? ?? ?? 0a 13 0b 2b 0b 12 0a 28 ?? ?? ?? 0a 13 0b 2b 00 07 11 0b 6f ?? ?? ?? 0a 00 00 11 09 17 58 13 09 11 09 09 fe 04 13 0e 11 0e 2d 97 } 		$a_01_1 = {54 00 65 00 63 00 68 00 6e 00 69 00 74 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}