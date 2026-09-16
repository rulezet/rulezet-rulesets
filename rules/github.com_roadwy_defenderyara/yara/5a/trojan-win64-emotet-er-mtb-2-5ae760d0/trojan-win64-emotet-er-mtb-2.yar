rule Trojan_Win64_Emotet_ER_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 d0 89 ca 29 c2 48 63 c2 4c 01 d0 0f b6 00 44 31 c8 41 88 00 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}