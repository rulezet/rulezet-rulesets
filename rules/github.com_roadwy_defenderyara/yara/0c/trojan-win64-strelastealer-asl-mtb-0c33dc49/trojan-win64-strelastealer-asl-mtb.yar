rule Trojan_Win64_StrelaStealer_ASL_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 10 48 89 7c 24 20 31 c9 ba 1a 00 00 00 45 31 c0 45 31 c9 4c 8b 25 06 28 05 00 41 ff d4 48 83 c4 10 48 89 f9 4c 8d 3d 2b f6 04 00 4c 89 fa 4c 89 eb 41 ff d5 41 b8 04 01 00 00 48 89 f1 31 d2 e8 14 93 04 00 } 		$a_01_1 = {63 38 64 37 39 64 35 35 2d 36 37 32 33 2d 34 64 38 35 2d 39 66 32 33 2d 37 32 35 32 65 32 65 32 62 66 66 31 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}