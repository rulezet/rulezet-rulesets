rule Trojan_Win64_Emotet_EM_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 f7 ea d1 fa 89 c8 c1 f8 1f 89 d3 29 c3 89 d8 6b c0 37 89 ce 29 c6 89 f0 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}