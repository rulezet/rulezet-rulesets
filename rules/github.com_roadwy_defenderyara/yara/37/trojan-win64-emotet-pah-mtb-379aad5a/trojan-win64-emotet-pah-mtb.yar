rule Trojan_Win64_Emotet_PAH_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b c2 48 98 48 8b 0d ?? ?? ?? ?? 0f b6 04 01 8b 4c 24 48 33 c8 8b c1 8b 4c 24 24 8b 54 24 20 2b d1 8b ca 03 4c 24 24 48 63 c9 48 8b 54 24 40 88 04 0a eb 94 48 8d 0d ce } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}