rule Trojan_Win64_Emotet_BM_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 32 4c 16 fb 41 88 4a fc 41 8b c9 41 f7 e8 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}