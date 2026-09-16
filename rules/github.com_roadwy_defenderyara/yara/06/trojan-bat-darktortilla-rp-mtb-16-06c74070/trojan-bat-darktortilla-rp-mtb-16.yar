rule Trojan_BAT_DarkTortilla_RP_MTB_16{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 16 9a 14 [0-10] 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 17 8d ?? ?? 00 01 25 16 03 8c ?? ?? 00 01 a2 25 0b 14 14 17 8d ?? ?? 00 01 25 16 17 9c 25 0c 28 ?? ?? 00 0a 0d ?? 13 09 2b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}