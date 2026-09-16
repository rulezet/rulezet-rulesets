rule Trojan_BAT_XWorm_ARX_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ARX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 3a 06 08 9a 28 ?? 00 00 0a 03 08 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 0d 09 59 08 1f 2b 5d 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 13 04 07 11 04 6f ?? 00 00 0a 26 08 17 58 0c } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}