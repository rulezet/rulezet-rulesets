rule Ransom_Win64_Filecoder_MX_MTB_2{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 30 48 8b 5c 24 18 e8 27 ff ff ff e9 49 ff ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}