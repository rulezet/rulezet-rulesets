rule Trojan_BAT_Remcos_ARM_MTB_7{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 15 02 07 03 28 12 00 00 06 2c 07 06 07 6f 35 00 00 0a 07 17 58 0b 07 02 8e 69 32 e5 } 		$a_01_1 = {0a 16 0b 2b 13 06 07 02 28 1f 00 00 06 07 6f 6c 00 00 0a a2 07 17 58 0b 07 02 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}