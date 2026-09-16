rule Ransom_Win64_Filecoder_MX_MTB_3{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } 		$a_01_1 = {78 6f 72 5f 6c 6f 63 6b 65 72 } 		$a_01_2 = {64 65 63 72 79 70 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}