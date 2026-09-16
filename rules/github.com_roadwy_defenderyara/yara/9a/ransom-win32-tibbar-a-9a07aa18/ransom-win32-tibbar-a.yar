rule Ransom_Win32_Tibbar_A{
	meta:
		description = "Ransom:Win32/Tibbar.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 3e 1c 24 4a 74 2f 3d 17 a5 3c 92 74 23 3d 15 04 6d 96 74 21 3d 20 16 33 aa 74 1a 3d 76 09 f1 c8 74 0e 3d 14 7a 51 e2 74 0c 3d 00 5a a0 e5 75 08 83 e7 bf eb 03 83 e7 ef 8d 85 d4 fd ff ff } 		$a_00_1 = {25 73 2c 23 32 20 25 73 00 00 00 41 44 4d 49 4e 24 00 00 63 73 63 63 2e 64 61 74 00 00 00 00 00 00 00 00 4f 00 6f 00 70 00 73 00 21 00 20 00 59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}