rule Trojan_Win64_BazarLoader_QW_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {0f 94 c0 83 f9 0a 0f 9c c3 30 c3 b8 7a 98 4f 76 41 0f 45 c5 } 		$a_02_1 = {0f b6 5d 57 0f b6 4d 56 89 da 30 ca ba ?? ?? ?? ?? 41 0f 45 d4 84 c9 89 d1 41 0f 45 cc 84 db 0f 44 ca eb ac } 	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}