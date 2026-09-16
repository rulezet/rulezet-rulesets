rule Ransom_MSIL_FileCoder_AYC_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 00 6f 00 6d 00 6e 00 69 00 61 00 2e 00 65 00 78 00 65 00 } 		$a_01_1 = {24 31 63 66 66 61 39 65 38 2d 37 31 62 64 2d 34 61 64 31 2d 62 35 31 34 2d 64 30 32 62 65 64 34 35 39 66 32 62 } 		$a_01_2 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } 		$a_01_3 = {55 73 65 72 73 5c 41 64 6d 69 6e 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 53 6f 6d 6e 69 61 } 	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}