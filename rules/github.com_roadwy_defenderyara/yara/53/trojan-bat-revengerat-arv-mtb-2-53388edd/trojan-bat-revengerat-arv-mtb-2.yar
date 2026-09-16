rule Trojan_BAT_RevengeRat_ARV_MTB_2{
	meta:
		description = "Trojan:BAT/RevengeRat.ARV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 1b 08 68 07 1f 64 06 1f 64 28 ?? ?? ?? 06 2c 08 72 ?? ?? ?? 70 0d de 13 08 17 58 0c 08 1a 31 e1 } 		$a_03_1 = {0a 14 0b 16 0c 16 0d 16 13 04 14 13 05 16 13 06 06 07 08 12 06 12 03 12 04 11 05 16 28 ?? 00 00 06 26 11 06 28 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}