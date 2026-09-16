rule Ransom_MSIL_Filecoder_MA_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 11 00 00 70 28 3a 00 00 06 7e 1e 00 00 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}