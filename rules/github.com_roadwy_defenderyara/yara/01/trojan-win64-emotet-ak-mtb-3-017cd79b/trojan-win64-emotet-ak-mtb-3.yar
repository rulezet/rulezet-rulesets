rule Trojan_Win64_Emotet_AK_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 08 48 63 4c 24 04 0f b6 04 08 89 04 24 48 8b 4c 24 20 48 63 44 24 04 31 d2 48 f7 74 24 50 8b 04 24 0f b6 0c 11 31 c8 88 c2 48 8b 44 24 10 48 63 4c 24 04 88 14 08 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}