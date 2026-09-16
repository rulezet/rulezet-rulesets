rule Trojan_BAT_Remcos_ARM_MTB_17{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 00 09 07 08 6f ?? 00 00 0a 00 00 de 0b 09 2c 07 09 6f ?? 00 00 0a 00 dc 08 28 } 		$a_03_1 = {0a 00 25 17 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 0a 06 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 de 23 0b 00 72 ?? 01 00 70 07 6f } 		$a_03_2 = {0a 00 25 17 6f ?? 00 00 0a 00 25 72 ?? 01 00 70 6f ?? 00 00 0a 00 0a 00 06 28 ?? 00 00 0a 26 00 de 05 26 00 00 de 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*3) >=6
 
}