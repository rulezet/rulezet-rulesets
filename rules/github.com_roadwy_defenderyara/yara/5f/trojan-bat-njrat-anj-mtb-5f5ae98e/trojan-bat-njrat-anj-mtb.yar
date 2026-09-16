rule Trojan_BAT_nJRat_ANJ_MTB{
	meta:
		description = "Trojan:BAT/nJRat.ANJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 d2 61 d2 81 0d 00 00 01 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 08 8e 69 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}