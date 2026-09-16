rule Trojan_BAT_Remcos_ARS_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 7e 03 01 00 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 19 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}