rule Trojan_Win64_Emotet_ED_MTB{
	meta:
		description = "Trojan:Win64/Emotet.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8a 04 02 44 32 44 1c 50 44 88 04 33 48 ff c3 49 3b de 7c b4 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}