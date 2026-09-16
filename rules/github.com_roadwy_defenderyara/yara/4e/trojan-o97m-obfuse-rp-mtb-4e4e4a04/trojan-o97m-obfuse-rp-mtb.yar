rule Trojan_O97M_Obfuse_RP_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.RP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5e 70 2a 6f 5e 2a 77 2a 65 2a 72 2a 73 5e 5e 2a 68 2a 65 2a 6c 5e 2a 6c 2a 2a 5e 2d 2a 77 2a 69 2a 6e 2a 5e 64 2a 6f 2a 77 5e 2a 73 2a 74 2a 79 2a 5e 6c 2a 65 2a 2a 68 2a 69 2a 5e 64 2a 64 2a 5e 65 2a 6e 5e 2a 2a 2d 2a 65 2a 78 2a 5e 65 2a 63 2a 75 2a 74 2a 5e 69 2a 6f 2a 6e 2a 70 6f 6c 5e 69 63 79 2a 2a 62 2a 79 70 5e 5e 61 73 73 2a 3b 2a 24 74 65 6d 70 66 69 6c 65 2a 2a 3d 2a 2a 5b 2a 69 2a 6f 2a 2e 2a 70 2a 61 2a 74 2a 68 2a 5d 2a 3a 3a 67 65 74 74 65 6d 2a 70 66 69 6c 65 2a 6e 61 6d 65 28 29 7c 72 65 6e 5e 61 6d 65 2d 69 74 5e 65 6d 2d 6e 65 77 6e 61 6d 65 7b 24 5f 2d 72 65 70 6c 61 63 65 27 74 6d 70 24 27 2c 27 65 78 65 27 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}