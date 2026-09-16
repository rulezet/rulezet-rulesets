rule Trojan_BAT_DarkTortilla_RP_MTB_14{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 06 17 8d 02 00 00 01 25 16 06 ?? ?? 00 00 01 a2 25 13 06 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 13 07 28 ?? 00 00 0a 13 08 [0-02] 13 0e 38 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}