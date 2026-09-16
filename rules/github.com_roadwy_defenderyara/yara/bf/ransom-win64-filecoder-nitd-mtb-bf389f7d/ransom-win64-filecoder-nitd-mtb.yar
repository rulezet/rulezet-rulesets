rule Ransom_Win64_Filecoder_NITD_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.NITD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 72 79 70 74 5f 6f 6e 6c 79 5f 74 68 65 73 65 5f 64 69 72 65 63 74 6f 72 69 65 73 } 		$a_01_1 = {73 65 72 76 69 63 65 73 5f 74 6f 5f 73 74 6f 70 } 		$a_01_2 = {63 65 73 5f 74 6f 5f 73 74 6f 70 } 		$a_01_3 = {74 65 6d 70 6f 72 61 72 79 5f 65 78 74 65 6e 73 69 6f 6e } 		$a_01_4 = {6f 6e 69 6f 6e 2f 63 68 61 74 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}