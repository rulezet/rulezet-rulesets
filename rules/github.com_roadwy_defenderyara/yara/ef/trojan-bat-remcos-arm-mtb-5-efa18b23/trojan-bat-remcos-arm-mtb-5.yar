rule Trojan_BAT_Remcos_ARM_MTB_5{
	meta:
		description = "Trojan:BAT/Remcos.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 05 16 11 06 6f 81 00 00 0a 00 00 08 11 05 16 11 05 8e 69 6f 82 00 00 0a 25 13 06 16 fe 02 } 		$a_03_1 = {7b 28 00 00 04 59 0c ?? ?? ?? ?? ?? ?? ?? ?? ?? 06 5a 06 5a 07 07 5a 58 08 08 5a 58 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}