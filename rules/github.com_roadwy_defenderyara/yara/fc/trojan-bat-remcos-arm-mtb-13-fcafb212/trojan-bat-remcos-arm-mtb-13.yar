rule Trojan_BAT_Remcos_ARM_MTB_13{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {16 9a 0c 08 19 8d 47 00 00 01 25 16 7e 2e 00 00 04 16 9a a2 25 17 7e 2e 00 00 04 17 9a a2 25 18 } 		$a_03_1 = {16 0b 2b 1a 00 06 07 02 07 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d dc } 		$a_01_2 = {54 6f 75 72 6e 61 6d 65 6e 74 4c 69 62 72 61 72 79 } 	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}