rule Trojan_BAT_DarkTortilla_RP_MTB_6{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1f 18 0a 72 45 01 00 70 28 a7 00 00 06 0b 07 74 0c 00 00 1b 28 68 00 00 06 00 de 0f 25 28 38 00 00 0a 0c 00 28 52 00 00 0a de 00 00 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}