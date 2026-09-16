rule Trojan_BAT_Remcos_AR_MTB_16{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {1c 2d 1d 26 07 28 ?? ?? ?? 0a 0c 08 16 08 8e 69 28 ?? ?? ?? 0a 08 0d de 25 } 		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}