rule Trojan_O97M_Obfuse_CA{
	meta:
		description = "Trojan:O97M/Obfuse.CA,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 53 68 65 6c 6c 28 } 		$a_02_1 = {20 3d 20 41 72 72 61 79 28 [0-10] 2c 20 [0-10] 2c 20 [0-10] 2c 20 49 6e 74 65 72 61 63 74 69 6f 6e 20 5f } 		$a_02_2 = {2e 53 68 61 70 65 73 28 [0-10] 20 2b } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}