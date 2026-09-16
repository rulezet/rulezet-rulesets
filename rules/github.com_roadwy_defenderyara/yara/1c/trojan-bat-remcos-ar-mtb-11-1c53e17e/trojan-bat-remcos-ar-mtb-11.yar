rule Trojan_BAT_Remcos_AR_MTB_11{
	meta:
		description = "Trojan:BAT/Remcos.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 3d 00 00 70 a2 25 17 7e 1d 00 00 0a a2 25 18 06 72 7d 00 00 70 6f } 		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}