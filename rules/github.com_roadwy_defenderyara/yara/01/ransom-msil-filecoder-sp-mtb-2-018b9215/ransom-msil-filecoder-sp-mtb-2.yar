rule Ransom_MSIL_FileCoder_SP_MTB_2{
	meta:
		description = "Ransom:MSIL/FileCoder.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 9a 0c 08 28 05 00 00 06 2c 0d 08 28 06 00 00 06 1f 64 28 17 00 00 0a 07 17 58 0b 07 06 8e 69 32 dd } 		$a_81_1 = {64 78 5f 72 61 6e 73 6f 6d 77 61 72 65 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 64 78 5f 72 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}