rule Ransom_Win64_Filecoder_MX_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 05 cc a7 11 00 31 c9 31 ff 48 89 fe 0f 1f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}