rule Trojan_BAT_Seraph_KAC_MTB{
	meta:
		description = "Trojan:BAT/Seraph.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 02 02 11 02 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}