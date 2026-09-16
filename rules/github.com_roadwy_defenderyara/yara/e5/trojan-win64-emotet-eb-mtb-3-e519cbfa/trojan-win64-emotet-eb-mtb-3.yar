rule Trojan_Win64_Emotet_EB_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 08 41 32 04 2a 41 88 02 49 ff c2 45 3b c6 72 c7 49 8b c1 48 8b 5c 24 50 48 8b 6c 24 58 48 8b 74 24 60 48 8b 7c 24 68 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}