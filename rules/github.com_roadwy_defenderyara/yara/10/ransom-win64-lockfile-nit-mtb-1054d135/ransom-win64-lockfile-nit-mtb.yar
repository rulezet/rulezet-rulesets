rule Ransom_Win64_LockFile_NIT_MTB{
	meta:
		description = "Ransom:Win64/LockFile.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 5c 24 30 48 8d 4d fc 48 89 4c 24 28 48 89 54 24 20 41 b9 00 00 00 00 41 b8 01 00 00 00 ba 00 00 00 00 48 89 c1 48 8b 05 11 ?? 13 00 ff d0 85 c0 0f 94 c0 84 c0 } 		$a_03_1 = {c7 44 24 60 01 00 10 00 ff 15 6e ?? 11 00 31 d2 48 8b 4e 28 ff 15 aa ?? 11 00 3d 02 01 00 00 0f 85 f4 fe ff ff 48 8b 4e 28 48 8d 54 24 30 ff 15 40 ?? 11 00 48 8d 05 81 fa ff ff 48 8b 4e 28 48 8d 54 24 30 48 89 84 24 28 01 00 00 ff 15 0a ?? 11 00 0f b6 46 40 83 66 44 fe 83 e0 f0 83 c8 05 88 46 40 f0 83 05 c1 0e 11 00 01 48 8b 4e 30 48 85 c9 74 06 ff 15 ba ?? 11 00 48 8d 4e 38 e8 49 d6 ff ff 48 8b 4e 28 ff 15 77 ?? 11 00 e9 87 fe ff ff } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}