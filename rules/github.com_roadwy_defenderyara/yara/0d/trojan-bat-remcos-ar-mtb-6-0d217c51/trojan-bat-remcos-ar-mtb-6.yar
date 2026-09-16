rule Trojan_BAT_Remcos_AR_MTB_6{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 06 1a 58 4a 04 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? ?? ?? 06 04 06 1a 58 4a 1b 58 19 59 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}