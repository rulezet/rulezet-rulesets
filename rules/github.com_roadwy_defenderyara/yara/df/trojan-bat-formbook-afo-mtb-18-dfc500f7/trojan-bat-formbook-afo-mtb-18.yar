rule Trojan_BAT_FormBook_AFO_MTB_18{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 14 07 08 02 7b ?? ?? ?? 04 08 91 28 ?? ?? ?? 0a 9d 08 17 58 0c 08 06 fe 04 0d 09 2d e4 } 		$a_03_1 = {26 2b 1c 00 02 7b ?? 00 00 04 07 6f ?? 00 00 0a 6f ?? 00 00 06 26 1f 64 28 ?? 00 00 0a 00 00 07 6f ?? 00 00 0a 16 fe 01 0c 08 2d d7 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}