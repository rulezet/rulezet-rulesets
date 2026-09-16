rule Trojan_Win64_Emotet_EB_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 01 41 32 04 29 41 88 01 49 ff c1 45 3b c4 72 c4 49 8b c3 48 8b 5c 24 30 48 8b 6c 24 38 48 8b 74 24 40 48 8b 7c 24 48 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}