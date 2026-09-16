rule Trojan_BAT_NjRAT_L_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 13 04 7e ?? 00 00 04 11 04 02 16 02 8e 69 28 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}