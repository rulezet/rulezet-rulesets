rule Ransom_Win64_Filecoder_C_MTB_2{
	meta:
		description = "Ransom:Win64/Filecoder.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 64 65 6c 65 74 65 56 53 53 } 		$a_01_1 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 46 69 6c 65 } 		$a_01_2 = {6d 61 69 6e 2e 73 63 61 6e 41 6e 64 45 6e 63 72 79 70 74 } 		$a_01_3 = {6d 61 69 6e 2e 73 68 6f 75 6c 64 45 6e 63 72 79 70 74 } 		$a_01_4 = {6d 61 69 6e 2e 73 68 6f 75 6c 64 45 78 63 6c 75 64 65 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=13
 
}