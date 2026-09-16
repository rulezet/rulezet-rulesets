rule Ransom_Win64_Filecoder_AMX_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.AMX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 68 65 61 72 74 62 72 65 61 6b 65 72 } 		$a_01_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 73 61 61 61 61 72 77 61 72 2f 6d 69 6d 69 63 6f 72 65 } 		$a_01_2 = {6c 69 74 63 72 79 70 74 } 		$a_01_3 = {65 6e 63 72 79 70 74 65 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}