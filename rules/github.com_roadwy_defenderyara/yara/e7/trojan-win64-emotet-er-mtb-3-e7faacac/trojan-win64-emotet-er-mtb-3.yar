rule Trojan_Win64_Emotet_ER_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 01 8b 4c 24 3c 33 c8 8b c1 48 63 4c 24 20 48 8b 54 24 50 88 04 0a } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}