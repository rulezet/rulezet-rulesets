rule Trojan_BAT_Remcos_SKI_MTB{
	meta:
		description = "Trojan:BAT/Remcos.SKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 02 03 06 07 04 28 32 00 00 06 00 00 07 17 58 0b 07 02 28 30 00 00 06 2f 0b 03 6f 96 00 00 0a 04 fe 04 2b 01 16 0c 08 2d d6 } 		$a_81_1 = {24 35 38 65 64 64 35 33 36 2d 31 61 63 61 2d 34 33 34 36 2d 39 37 63 65 2d 64 36 30 36 62 33 31 31 31 66 35 31 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}