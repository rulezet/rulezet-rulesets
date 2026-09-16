rule Ransom_Win64_Encoder_MX_MTB{
	meta:
		description = "Ransom:Win64/Encoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 65 6c 65 61 73 65 5c 45 6e 63 6f 64 65 72 20 41 45 53 2b 52 53 41 2e 70 64 62 } 		$a_01_1 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 2e 00 6b 00 65 00 79 00 } 		$a_01_2 = {43 72 79 70 74 45 6e 63 72 79 70 74 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}