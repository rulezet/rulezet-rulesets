rule Trojan_BAT_DarkTortilla_RP_MTB_8{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 8e 69 17 da 0b 16 0c 2b 1a 08 1b 5d 16 fe 01 0d 09 2c 0b 02 08 02 08 91 1f 32 61 b4 9c 00 00 08 17 d6 0c 08 07 31 e2 02 0a 2b 00 06 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}