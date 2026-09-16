rule Trojan_BAT_Remcos_ARC_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.ARC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 02 11 01 02 11 01 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 20 06 00 00 00 7e ?? 01 00 04 7b } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}