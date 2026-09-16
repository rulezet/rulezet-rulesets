rule Trojan_Win64_Emotet_EN_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 38 99 b9 41 00 00 00 f7 f9 8b c2 48 98 48 8b 4c 24 28 0f b6 04 01 8b 4c 24 40 33 c8 8b c1 48 63 4c 24 38 48 8b 54 24 30 88 04 0a } 	condition:
		((#a_01_0  & 1)*7) >=7
 
}