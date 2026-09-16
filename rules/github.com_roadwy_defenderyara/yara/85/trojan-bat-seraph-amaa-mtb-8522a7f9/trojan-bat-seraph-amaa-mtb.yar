rule Trojan_BAT_Seraph_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 01 11 03 11 00 11 03 91 72 ?? 00 00 70 28 ?? 00 00 06 59 d2 9c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}