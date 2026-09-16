rule Trojan_Win64_Emotet_AK_MTB{
	meta:
		description = "Trojan:Win64/Emotet.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 01 8b 4c 24 48 33 c8 8b c1 8b 4c 24 24 8b 54 24 20 2b d1 8b ca 03 4c 24 24 48 63 c9 48 8b 54 24 30 88 04 0a } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}