rule Trojan_BAT_Remcos_ARS_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 16 0c 2b 46 03 08 03 8e 69 5d 1b 59 1b 58 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 0a 03 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}