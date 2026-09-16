rule Trojan_BAT_Remcos_ARM_MTB_16{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 02 8e 69 20 00 10 00 00 1f 40 28 ?? 00 00 06 0a 16 0b 25 06 02 02 8e 69 12 01 28 ?? 00 00 06 26 7e ?? 00 00 0a 0c 7e ?? 00 00 0a 16 20 ff 0f 00 00 28 ?? 00 00 0a 7e ?? 00 00 0a 1a 12 02 28 } 		$a_01_1 = {0a 16 0b 2b 22 06 07 9a 0c 08 6f 2f 00 00 0a 6f 30 00 00 0a 02 28 14 00 00 0a 2c 07 08 6f 31 00 00 0a 2a 07 17 58 0b 07 06 8e 69 32 d8 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}