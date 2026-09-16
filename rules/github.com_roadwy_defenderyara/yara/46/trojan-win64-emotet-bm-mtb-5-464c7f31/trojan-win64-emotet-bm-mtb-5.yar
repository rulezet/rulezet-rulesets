rule Trojan_Win64_Emotet_BM_MTB_5{
	meta:
		description = "Trojan:Win64/Emotet.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 8a 0c 08 43 32 0c 02 41 88 08 49 ff c0 48 ff ce 74 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}