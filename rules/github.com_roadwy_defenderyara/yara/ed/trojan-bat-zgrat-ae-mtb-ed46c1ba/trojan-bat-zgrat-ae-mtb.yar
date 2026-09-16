rule Trojan_BAT_zgRAT_AE_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 04 20 00 01 00 00 0e 04 50 74 ?? 00 00 01 0e 04 50 28 ?? 00 00 0a 28 ?? ?? 00 06 05 6f } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}