rule Ransom_Win64_FileCoder_BA_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {66 69 6c 65 5f 78 6f 72 5f 6c 6f 63 6b 65 72 } 		$a_81_1 = {64 65 63 72 79 70 74 } 		$a_81_2 = {52 45 41 44 4d 45 2e 74 78 74 } 		$a_81_3 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}