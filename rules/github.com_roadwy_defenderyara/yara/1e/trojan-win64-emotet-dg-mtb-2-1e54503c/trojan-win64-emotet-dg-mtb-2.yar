rule Trojan_Win64_Emotet_DG_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.DG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 d0 41 8b c4 41 ff c4 6b d2 43 2b c2 48 63 d0 48 63 05 1c a4 06 00 48 0f af c8 48 63 05 21 a4 06 00 48 2b c8 48 8d 04 89 48 03 d0 48 8b 44 24 28 42 0f b6 8c 32 f0 f7 04 00 41 32 4c 00 ff 43 88 4c 18 ff 44 3b 64 24 20 72 98 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}