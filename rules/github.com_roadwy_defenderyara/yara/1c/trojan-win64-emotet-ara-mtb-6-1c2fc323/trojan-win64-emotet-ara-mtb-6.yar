rule Trojan_Win64_Emotet_ARA_MTB_6{
	meta:
		description = "Trojan:Win64/Emotet.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 8b c8 b8 79 78 78 78 41 f7 e8 41 ff c0 c1 fa 03 8b c2 c1 e8 1f 03 d0 6b c2 11 2b c8 48 63 c1 48 8d 0d b7 de 07 00 8a 04 08 42 32 04 16 41 88 02 49 ff c2 44 3b c5 72 c7 } 		$a_01_1 = {41 8b c8 b8 b7 60 0b b6 41 f7 e8 41 03 d0 41 ff c0 c1 fa 05 8b c2 c1 e8 1f 03 d0 6b c2 2d 2b c8 48 63 c1 48 8d 0d 04 f4 07 00 8a 04 08 42 32 04 16 41 88 02 49 ff c2 44 3b c5 72 c4 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}