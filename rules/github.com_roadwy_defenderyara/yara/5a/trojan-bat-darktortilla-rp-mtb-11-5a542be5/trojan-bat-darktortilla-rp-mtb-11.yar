rule Trojan_BAT_DarkTortilla_RP_MTB_11{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 18 0a 72 ?? ?? 00 70 0c 08 72 ?? ?? 00 70 72 ?? ?? 00 70 6f ?? ?? 00 0a 28 ?? ?? 00 06 0b 07 74 ?? ?? 00 1b 28 ?? ?? 00 06 00 de 0f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}