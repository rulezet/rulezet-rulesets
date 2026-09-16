rule Trojan_BAT_nJRat_ANJ_MTB_4{
	meta:
		description = "Trojan:BAT/nJRat.ANJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 09 8d 1e 00 00 01 13 0d 11 0d 16 11 04 a2 00 11 0d 17 11 05 08 17 28 ?? ?? ?? 0a a2 00 11 0d 18 11 06 08 17 28 ?? ?? ?? 0a a2 00 11 0d 19 11 07 08 17 28 } 		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}