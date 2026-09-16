rule Trojan_Win64_Emotet_ARA_MTB_5{
	meta:
		description = "Trojan:Win64/Emotet.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 38 ff c0 89 44 24 38 8b 44 24 68 39 44 24 38 73 42 48 63 44 24 38 48 8b 4c 24 60 0f b6 04 01 89 44 24 40 8b 44 24 38 99 b9 2e 00 00 00 f7 f9 8b c2 48 98 48 8b 4c 24 28 0f b6 04 01 8b 4c 24 40 33 c8 8b c1 48 63 4c 24 38 48 8b 54 24 30 88 04 0a eb aa } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}