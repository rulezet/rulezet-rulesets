rule Trojan_BAT_DarkTortilla_RP_MTB_3{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 0b 2b 0c 07 18 d8 1f 18 28 52 00 00 0a 0b 00 07 1f 18 5d 16 fe 01 0c 08 2c e9 07 0a 2b 00 06 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}