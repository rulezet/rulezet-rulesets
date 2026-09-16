rule Trojan_Win64_Emotet_PBG_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e6 8b c6 8b ce 2b c2 ff c6 d1 ?? 03 c2 c1 e8 ?? 6b c0 ?? 2b c8 48 63 c1 42 0f b6 04 10 43 32 44 07 ?? 41 88 40 ?? 41 3b f4 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}