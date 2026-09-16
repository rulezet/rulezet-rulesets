rule Trojan_Win64_IcedID_EB_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 54 24 10 48 89 4c 24 08 eb 1b 80 44 24 40 5a c6 44 24 41 4b eb b8 80 44 24 46 30 c6 44 24 47 22 e9 6d ff ff ff } 	condition:
		((#a_01_0  & 1)*8) >=8
 
}