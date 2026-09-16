rule Ransom_MSIL_FileCoder_AB_MTB{
	meta:
		description = "Ransom:MSIL/FileCoder.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 1f 0b 64 11 0a 1f 15 62 60 13 0d 11 1a 20 27 62 a9 d1 5a 20 8e f4 da a2 61 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}