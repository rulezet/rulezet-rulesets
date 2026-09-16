rule Trojan_BAT_Remcos_ARO_MTB_11{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 00 06 6f b6 00 00 0a 0c 2b 1e 12 02 28 b7 00 00 0a 0d 09 6f b5 00 00 06 16 fe 01 13 04 11 04 2c 07 09 6f b8 00 00 06 00 12 02 } 		$a_01_1 = {0a 2b 1d 12 00 28 b7 00 00 0a 0b 07 6f b5 00 00 06 16 fe 01 0c 08 2c 08 07 02 6f b7 00 00 06 00 12 00 28 b8 00 00 0a 2d da } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}