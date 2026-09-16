rule Ransom_Win64_Encoder_PF_MTB{
	meta:
		description = "Ransom:Win64/Encoder.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 4f 54 5f 43 4f 4e 4e 45 43 54 45 44 } 		$a_01_1 = {5c 00 52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 2e 00 74 00 78 00 74 00 } 		$a_01_2 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3) >=5
 
}