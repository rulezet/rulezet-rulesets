rule Trojan_BAT_DarkTortilla_RP_MTB_15{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 20 cc 00 00 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 06 0b 07 74 ?? ?? 00 1b 28 ?? ?? 00 06 00 de 0f 25 28 ?? ?? 00 0a 0c 00 28 ?? ?? 00 0a de 00 00 2a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}