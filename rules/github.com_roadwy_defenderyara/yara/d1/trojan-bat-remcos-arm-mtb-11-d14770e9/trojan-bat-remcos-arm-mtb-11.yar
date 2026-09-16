rule Trojan_BAT_Remcos_ARM_MTB_11{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 3a 16 0b 2b 13 02 06 07 03 04 28 ?? 00 00 06 28 ?? 00 00 06 07 17 58 0b 07 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0c 08 2d d4 } 		$a_03_1 = {02 03 04 6f ?? 00 00 0a 0a 0e 04 05 6f ?? 00 00 0a 59 0b 06 07 05 28 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}