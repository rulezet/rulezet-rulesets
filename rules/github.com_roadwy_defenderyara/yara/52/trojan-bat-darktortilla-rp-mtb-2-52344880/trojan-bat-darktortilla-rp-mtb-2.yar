rule Trojan_BAT_DarkTortilla_RP_MTB_2{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 20 c8 01 00 00 61 13 04 11 04 18 62 13 04 11 04 07 19 62 61 13 04 11 04 13 05 16 13 06 2b 06 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}