rule Ransom_Win64_Filecoder_MX_MTB_4{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8d 8d d0 03 00 00 4c 8b 85 f8 04 00 00 48 8d 55 c0 48 8d 45 c0 c7 44 24 28 01 00 00 00 48 8d 4d b0 48 89 4c 24 20 48 89 c1 e8 72 13 00 00 48 8b 8d 00 05 00 00 48 8b 95 f8 04 00 00 48 8d 45 c0 49 89 c9 49 89 d0 ba } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}