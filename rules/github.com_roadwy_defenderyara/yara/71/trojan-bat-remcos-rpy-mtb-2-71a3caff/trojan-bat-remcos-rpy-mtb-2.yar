rule Trojan_BAT_Remcos_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 02 07 18 5a 18 6f 8a 00 00 0a 1f 10 28 8b 00 00 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d dc } 		$a_01_1 = {34 00 44 00 35 00 41 00 39 00 7e 00 7e 00 33 00 7e 00 7e 00 7e 00 30 00 34 00 7e 00 7e 00 7e 00 46 00 46 00 46 00 46 00 7e 00 7e 00 42 00 38 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 34 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 30 00 38 00 7e 00 7e 00 7e 00 7e 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}