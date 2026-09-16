rule Ransom_MSIL_FileCryptor_A_MTB{
	meta:
		description = "Ransom:MSIL/FileCryptor.A!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 20 7c 0c 00 00 28 e4 00 00 06 28 03 00 00 06 39 a5 00 00 00 } 		$a_01_1 = {45 06 00 00 00 12 00 00 00 cb ff ff ff 00 00 00 00 bb ff ff ff cb ff ff ff 2d 00 00 00 } 		$a_01_2 = {24 32 38 32 62 38 64 38 36 2d 66 33 33 66 2d 34 34 31 65 2d 38 62 62 35 2d 39 35 39 30 33 33 35 31 62 65 33 39 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}