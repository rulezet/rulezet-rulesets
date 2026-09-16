rule Trojan_BAT_nJRat_ANJ_MTB_3{
	meta:
		description = "Trojan:BAT/nJRat.ANJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 2b 41 7e 07 00 00 04 11 04 6f ?? ?? ?? 0a 74 03 00 00 01 6f ?? ?? ?? 0a 2c 25 11 04 08 fe 01 16 fe 01 2c 17 7e 07 00 00 04 08 7e 07 00 00 04 11 04 6f } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}