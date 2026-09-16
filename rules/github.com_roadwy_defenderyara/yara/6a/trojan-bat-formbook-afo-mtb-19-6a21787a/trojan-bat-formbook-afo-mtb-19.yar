rule Trojan_BAT_FormBook_AFO_MTB_19{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 2b 4e 00 08 11 04 08 8e 69 5d 02 08 11 04 08 8e 69 5d 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 08 11 04 17 58 08 8e 69 5d 91 } 		$a_01_1 = {53 00 77 00 69 00 74 00 63 00 68 00 62 00 6f 00 61 00 72 00 64 00 53 00 65 00 72 00 76 00 65 00 72 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}