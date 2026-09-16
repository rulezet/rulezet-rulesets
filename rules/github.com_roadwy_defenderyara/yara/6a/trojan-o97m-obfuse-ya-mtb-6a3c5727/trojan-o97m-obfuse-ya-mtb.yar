rule Trojan_O97M_Obfuse_YA_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {28 55 73 65 72 46 6f 72 6d [0-02] 2e 54 65 78 74 42 6f 78 [0-02] 2e 54 65 78 74 29 } 		$a_00_1 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}