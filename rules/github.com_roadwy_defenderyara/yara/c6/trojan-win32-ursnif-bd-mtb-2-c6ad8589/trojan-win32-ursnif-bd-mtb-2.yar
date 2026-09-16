rule Trojan_Win32_Ursnif_BD_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c5 03 f7 83 e8 52 0f b6 c0 0f af c7 69 d0 7f a4 00 00 b0 57 8a ca c0 e1 04 02 ca 2a c1 0f b6 c8 8d 04 11 69 c0 13 14 58 1e 2b d0 8b 44 24 10 05 7c 25 39 03 8d 14 50 a1 ?? ?? ?? ?? 03 c7 03 d2 69 f8 7f a4 00 00 2b d1 0f b7 c6 8d 4a 9f 2b d6 81 ef 7b 36 03 00 88 0d ?? ?? ?? ?? 0f af f8 8d 43 ae 03 c2 0f b7 c0 8b d7 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}