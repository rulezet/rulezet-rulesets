rule Trojan_BAT_ZgRAT_KAA_MTB_2{
	meta:
		description = "Trojan:BAT/ZgRAT.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 08 09 06 09 91 7e ?? 00 00 04 59 d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}