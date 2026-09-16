rule Trojan_BAT_Remcos_EF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0a 0b 07 72 86 75 00 70 28 04 00 00 06 18 14 28 07 00 00 0a 0c 08 72 9c 75 00 70 28 04 00 00 06 17 18 8d 01 00 00 01 0d 09 16 16 8c 0c 00 00 01 a2 09 28 07 00 00 0a 26 2a } 		$a_01_1 = {70 0a 02 6f 17 00 00 0a 17 59 0b 2b 17 06 02 07 6f 18 00 00 0a 8c 20 00 00 01 28 19 00 00 0a 0a 07 17 59 0b 07 16 2f e5 06 2a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}