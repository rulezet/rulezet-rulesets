rule Trojan_BAT_DarkTortilla_RP_MTB_4{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 06 19 5d 16 fe 01 13 07 11 07 2c 0d 06 11 06 06 11 06 91 1f 26 61 b4 9c 00 00 11 06 17 d6 13 06 11 06 11 05 31 d9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}