rule Trojan_Win64_Emotet_EK_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d3 29 c3 89 d8 6b c0 ?? 89 ce 29 c6 89 f0 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}