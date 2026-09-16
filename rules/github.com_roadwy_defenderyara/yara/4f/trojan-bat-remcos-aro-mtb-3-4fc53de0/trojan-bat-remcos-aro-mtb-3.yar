rule Trojan_BAT_Remcos_ARO_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 da 0b 16 0c 2b 11 02 08 02 08 91 20 d2 00 00 00 61 b4 9c 08 1d d6 0c 08 07 31 eb 14 0a 00 28 ?? 01 00 0a 0d 09 02 28 ?? 01 00 0a 00 09 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}