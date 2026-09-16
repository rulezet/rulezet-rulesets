rule Trojan_BAT_FormBook_ACM_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 1e 08 11 04 9a 13 08 09 11 08 1f 10 28 ?? ?? ?? 0a b4 6f ?? ?? ?? 0a 00 11 04 17 d6 13 04 00 11 04 08 8e 69 fe 04 13 09 11 09 } 		$a_01_1 = {57 00 32 00 50 00 69 00 7a 00 7a 00 61 00 4f 00 72 00 64 00 65 00 72 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}