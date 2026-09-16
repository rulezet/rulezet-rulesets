rule Trojan_Win64_Emotet_PAK_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.PAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea c1 fa 03 89 c8 c1 f8 1f 29 c2 89 d0 01 c0 01 d0 c1 e0 04 89 ca 29 c2 48 63 c2 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 0f 9c c0 84 c0 0f } 		$a_03_1 = {89 c8 f7 ea d1 fa 89 c8 c1 f8 1f 89 d3 29 c3 89 d8 6b c0 37 89 ce 29 c6 89 f0 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 3b 85 ?? ?? ?? ?? 0f 9c c0 84 c0 0f 85 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}