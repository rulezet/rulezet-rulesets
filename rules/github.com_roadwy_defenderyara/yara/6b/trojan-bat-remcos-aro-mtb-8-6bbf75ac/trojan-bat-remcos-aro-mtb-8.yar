rule Trojan_BAT_Remcos_ARO_MTB_8{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 02 28 ?? ?? ?? 0a 0c dd 08 00 00 00 26 14 0d dd 33 00 00 00 73 e8 00 00 0a 13 04 08 73 e9 00 00 0a 13 05 11 05 11 04 06 07 6f ?? ?? ?? 0a 16 73 eb 00 00 0a 13 06 11 06 } 		$a_01_1 = {48 00 75 00 69 00 64 00 54 00 65 00 61 00 63 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}