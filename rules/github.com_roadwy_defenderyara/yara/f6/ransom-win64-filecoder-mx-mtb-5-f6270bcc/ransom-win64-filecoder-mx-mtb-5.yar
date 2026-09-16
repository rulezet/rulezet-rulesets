rule Ransom_Win64_Filecoder_MX_MTB_5{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 65 6e 63 72 79 70 74 65 64 } 		$a_01_1 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } 		$a_01_2 = {74 6f 20 72 65 73 74 6f 72 65 20 74 68 65 6d } 		$a_01_3 = {6d 65 73 73 61 67 65 20 77 69 6c 6c 20 62 65 20 64 65 6c 65 74 65 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}