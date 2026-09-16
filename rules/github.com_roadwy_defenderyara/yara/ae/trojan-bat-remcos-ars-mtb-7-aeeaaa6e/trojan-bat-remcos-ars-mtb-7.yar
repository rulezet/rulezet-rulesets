rule Trojan_BAT_Remcos_ARS_MTB_7{
	meta:
		description = "Trojan:BAT/Remcos.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 38 3f 00 00 00 28 ?? ?? ?? 06 75 01 00 00 1b 28 ?? ?? ?? 0a 0b d0 01 00 00 01 28 ?? ?? ?? 0a 72 01 00 00 70 28 ?? ?? ?? 0a 07 14 6f ?? ?? ?? 0a 75 02 00 00 1b 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}