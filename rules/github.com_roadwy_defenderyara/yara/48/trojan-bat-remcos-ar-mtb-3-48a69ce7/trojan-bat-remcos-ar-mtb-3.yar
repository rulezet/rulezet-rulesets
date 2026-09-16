rule Trojan_BAT_Remcos_AR_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 08 06 08 8e 69 5d 91 09 06 91 61 d2 6f ?? ?? ?? 0a 06 17 58 0a 06 09 8e 69 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}