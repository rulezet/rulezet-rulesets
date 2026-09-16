rule Trojan_BAT_Remcos_ARO_MTB_14{
	meta:
		description = "Trojan:BAT/Remcos.ARO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {5d 91 1e 5d 0b 02 7b ?? 00 00 04 06 18 58 02 7b ?? 00 00 04 5d 91 0c 02 7b ?? 00 00 04 06 19 58 02 7b ?? 00 00 04 5d 91 0d 02 03 06 91 28 } 		$a_01_1 = {69 00 6e 00 76 00 65 00 73 00 74 00 64 00 69 00 72 00 65 00 63 00 74 00 69 00 6e 00 73 00 75 00 72 00 61 00 6e 00 63 00 65 00 2e 00 63 00 6f 00 6d 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}