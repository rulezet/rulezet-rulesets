rule Trojan_BAT_FormBook_AFO_MTB_8{
	meta:
		description = "Trojan:BAT/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 09 2b 19 00 06 7b ?? 01 00 04 11 24 11 09 91 6f ?? 01 00 0a 00 00 11 09 17 58 13 09 11 09 11 16 fe 04 13 25 } 		$a_01_1 = {44 00 6f 00 41 00 6e 00 43 00 61 00 4e 00 68 00 61 00 6e 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}