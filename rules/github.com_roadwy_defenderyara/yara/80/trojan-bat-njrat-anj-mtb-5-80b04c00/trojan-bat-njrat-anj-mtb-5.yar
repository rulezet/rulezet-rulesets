rule Trojan_BAT_nJRat_ANJ_MTB_5{
	meta:
		description = "Trojan:BAT/nJRat.ANJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 18 00 00 0a 0a 06 28 19 00 00 0a 03 6f 1a 00 00 0a 6f 1b 00 00 0a 0b 73 1c 00 00 0a 0c 08 07 6f 1d 00 00 0a 00 08 18 6f 1e 00 00 0a 00 08 6f 1f 00 00 0a 02 16 02 8e 69 6f 20 00 00 0a 0d 09 13 04 2b 00 11 04 } 		$a_01_1 = {54 72 69 70 6c 65 44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}