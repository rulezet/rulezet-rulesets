rule Trojan_BAT_DarkTortilla_RP_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 18 d8 1f 18 30 05 06 18 d8 2b 02 1f 18 0a 00 06 1f 18 5d 16 fe 01 0c 08 2c e4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}