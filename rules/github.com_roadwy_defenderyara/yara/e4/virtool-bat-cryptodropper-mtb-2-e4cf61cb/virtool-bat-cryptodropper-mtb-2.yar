rule VirTool_BAT_CryptoDropper_MTB_2{
	meta:
		description = "VirTool:BAT/CryptoDropper!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 61 73 6f 4d 61 6e 2e 65 78 65 } 		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 } 		$a_01_2 = {2e 4c 6f 61 64 28 5b 43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 62 61 73 65 36 34 53 74 72 69 6e 67 28 } 		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 22 2c 20 2e 57 69 6e 64 6f 77 53 74 79 6c 65 20 3d 20 50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 79 6c 65 2e 48 69 64 64 65 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}