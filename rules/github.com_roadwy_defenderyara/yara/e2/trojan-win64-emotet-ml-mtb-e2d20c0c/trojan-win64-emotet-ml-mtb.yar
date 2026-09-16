rule Trojan_Win64_Emotet_ML_MTB{
	meta:
		description = "Trojan:Win64/Emotet.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 6d 6f 74 65 74 20 64 75 6d 6d 79 20 44 4c 4c } 		$a_01_1 = {45 6d 6f 74 65 74 20 6c 6f 61 64 65 72 20 62 75 6e 64 6c 65 } 		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_3 = {64 75 6d 6d 79 2d 64 6c 6c 2e 64 6c 6c } 		$a_01_4 = {68 65 6c 6c 6f 5f 66 72 6f 6d 5f } 		$a_01_5 = {6c 6f 61 64 65 64 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=14
 
}