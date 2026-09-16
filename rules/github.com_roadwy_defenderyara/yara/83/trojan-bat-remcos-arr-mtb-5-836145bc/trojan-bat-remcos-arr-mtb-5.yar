rule Trojan_BAT_Remcos_ARR_MTB_5{
	meta:
		description = "Trojan:BAT/Remcos.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 06 72 97 18 00 70 6f ?? ?? ?? 0a 74 02 00 00 1b 0c 08 28 ?? ?? ?? 0a 00 07 08 6f ?? ?? ?? 0a 00 07 06 72 a3 18 00 70 6f ?? ?? ?? 0a 74 02 00 00 1b 6f ?? ?? ?? 0a 00 07 06 72 af 18 00 70 6f ?? ?? ?? 0a 74 02 00 00 1b 6f ?? ?? ?? 0a 00 02 28 } 		$a_01_1 = {53 00 65 00 68 00 69 00 72 00 54 00 61 00 68 00 6d 00 69 00 6e 00 45 00 74 00 6d 00 65 00 4f 00 79 00 75 00 6e 00 75 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}