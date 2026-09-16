rule Trojan_BAT_Remcos_ARO_MTB_10{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 0a 38 17 00 00 00 00 72 93 00 00 70 28 ?? ?? ?? 06 0a dd 09 00 00 00 26 dd 00 00 00 00 06 2c e6 06 2a } 		$a_01_1 = {73 29 00 00 0a 0a 02 28 06 00 00 2b 6f 2b 00 00 0a 0b 38 0e 00 00 00 07 6f 2c 00 00 0a 0c 06 08 6f 2d 00 00 0a 07 6f 2e 00 00 0a 2d ea } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}