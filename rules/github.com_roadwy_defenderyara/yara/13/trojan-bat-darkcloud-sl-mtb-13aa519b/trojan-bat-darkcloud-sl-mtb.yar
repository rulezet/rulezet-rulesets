rule Trojan_BAT_DarkCloud_SL_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 9a 13 06 11 06 6f 77 01 00 0a 19 fe 04 13 07 11 07 2c 04 16 0d 2b 16 00 00 11 05 17 d6 13 05 11 05 11 04 8e 69 fe 04 13 08 11 08 2d cf } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}