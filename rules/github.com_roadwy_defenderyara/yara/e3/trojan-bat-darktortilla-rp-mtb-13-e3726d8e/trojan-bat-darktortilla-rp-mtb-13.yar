rule Trojan_BAT_DarkTortilla_RP_MTB_13{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 0a 00 06 1f 18 fe 02 16 fe 01 0c 08 2c 06 1f 18 0a 00 2b 10 00 06 1f 18 fe 04 0d 09 2c 04 1f 18 0a 00 00 00 00 06 1f 18 5d 16 fe 01 13 04 11 04 2c cf 06 17 da 17 d6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}