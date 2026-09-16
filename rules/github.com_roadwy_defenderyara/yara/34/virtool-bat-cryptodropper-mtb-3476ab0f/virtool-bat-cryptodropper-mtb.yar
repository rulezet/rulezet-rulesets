rule VirTool_BAT_CryptoDropper_MTB{
	meta:
		description = "VirTool:BAT/CryptoDropper!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6e 68 6f 73 74 2e 65 78 65 } 		$a_01_1 = {73 65 74 5f 50 61 73 73 77 6f 72 64 } 		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_01_3 = {55 45 39 54 56 41 3d 3d } 		$a_01_4 = {62 6d 56 30 49 48 4e 30 59 58 4a 30 49 47 4e 7a 63 6e 4e 7a } 		$a_01_5 = {61 48 52 30 63 44 6f 76 4c } 		$a_01_6 = {59 6d 6c 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}