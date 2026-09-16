rule Trojan_BAT_Remcos_ARO_MTB_12{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 00 07 13 07 16 13 08 2b 43 11 07 11 08 9a 0d 00 09 6f ?? ?? ?? 0a 72 a5 00 00 70 6f ?? ?? ?? 0a 16 fe 01 13 09 11 09 2d 1c 00 12 02 08 8e 69 17 58 28 ?? ?? ?? 2b 00 08 08 8e 69 17 59 09 6f ?? ?? ?? 0a a2 00 00 11 08 17 58 13 08 11 08 11 07 8e 69 fe 04 13 09 11 09 2d af } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}