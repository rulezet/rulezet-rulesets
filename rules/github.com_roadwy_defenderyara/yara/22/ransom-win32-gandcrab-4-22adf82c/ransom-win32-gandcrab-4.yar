rule Ransom_Win32_GandCrab_4{
	meta:
		description = "Ransom:Win32/GandCrab,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 4f 02 8d 7f 04 8a d1 8a c1 80 e1 f0 c0 e0 06 0a 47 fd 80 e2 fc c0 e1 02 0a 4f fb c0 e2 04 0a 57 fc 88 0c 1e 88 54 1e 01 88 44 1e 02 83 c6 03 83 6d f8 01 75 ca } 		$a_02_1 = {81 fe 37 0e 00 00 7d 14 6a 00 6a 00 6a 00 6a 00 ff d7 6a 00 6a 00 ff 15 ?? ?? 41 00 0f be 1c 1e e8 7b ff ff ff 32 c3 8b 5d fc 88 04 1e 46 3b 75 f8 7c cd } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}