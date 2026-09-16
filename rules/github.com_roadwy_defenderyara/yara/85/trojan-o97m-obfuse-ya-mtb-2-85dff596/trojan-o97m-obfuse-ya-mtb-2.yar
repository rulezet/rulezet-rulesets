rule Trojan_O97M_Obfuse_YA_MTB_2{
	meta:
		description = "Trojan:O97M/Obfuse.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 54 45 4d 50 25 5c [0-40] 2e 65 78 65 } 		$a_03_1 = {2e 52 75 6e 20 [0-40] 2c } 		$a_00_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}