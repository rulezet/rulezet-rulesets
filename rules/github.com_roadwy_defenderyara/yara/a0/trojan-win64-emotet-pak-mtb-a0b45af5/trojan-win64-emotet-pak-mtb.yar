rule Trojan_Win64_Emotet_PAK_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ef 03 d7 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 6b c2 ?? 2b c8 48 63 c1 42 0f b6 0c 00 44 8d 47 02 43 32 4c 11 fb b8 ?? ?? ?? ?? 41 88 4a fb 41 8d 48 ff f7 e9 03 d1 8b cf c1 fa 04 8b c2 c1 e8 1f 03 d0 6b c2 1c 2b c8 48 8b 05 ?? ?? ?? ?? ff c1 48 63 c9 0f b6 0c 01 b8 93 24 49 92 42 32 4c 16 fb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}