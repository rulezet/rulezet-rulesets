rule Trojan_BAT_Remcos_AR_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 01 02 11 01 91 72 ?? 00 00 70 28 ?? 00 00 06 59 d2 9c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}