rule Trojan_Win64_Emotet_AM_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 84 24 f0 0b 00 00 99 b9 ?? 00 00 00 f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 fc 0b 00 00 33 c8 8b c1 } 	condition:
		((#a_03_0  & 1)*6) >=6
 
}