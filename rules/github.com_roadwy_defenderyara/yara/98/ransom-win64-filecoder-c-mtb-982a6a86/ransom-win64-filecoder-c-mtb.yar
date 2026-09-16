rule Ransom_Win64_Filecoder_C_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 0f 43 c7 45 0f b6 0e 44 32 08 48 8b 4f } 		$a_01_1 = {73 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 } 		$a_01_2 = {54 00 72 00 65 00 6e 00 64 00 20 00 4d 00 69 00 63 00 72 00 6f 00 } 		$a_01_3 = {76 00 65 00 65 00 61 00 6d 00 2e 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=20
 
}