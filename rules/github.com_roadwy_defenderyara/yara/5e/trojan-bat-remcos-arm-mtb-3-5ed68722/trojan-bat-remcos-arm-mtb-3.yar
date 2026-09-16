rule Trojan_BAT_Remcos_ARM_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 38 16 0b 2b 21 08 06 07 28 ?? ?? ?? 06 13 09 09 12 09 28 ?? ?? ?? 0a 8c 07 00 00 01 28 ?? ?? ?? 06 26 07 17 58 0b 07 08 28 ?? ?? ?? 06 fe 04 13 06 11 06 2d d0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}