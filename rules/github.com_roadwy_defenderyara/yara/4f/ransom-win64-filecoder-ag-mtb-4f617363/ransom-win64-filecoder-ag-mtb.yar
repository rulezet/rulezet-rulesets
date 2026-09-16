rule Ransom_Win64_FileCoder_AG_MTB{
	meta:
		description = "Ransom:Win64/FileCoder.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c0 48 8b 9c 24 c8 02 00 00 48 8b 8c 24 d0 02 00 00 48 8d 3d 0e 4f 02 00 be 06 00 00 00 e8 f1 e2 f9 ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}