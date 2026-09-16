rule Trojan_Win32_ValleyRat_BSA_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 0c 8b 4c 24 04 85 d2 74 69 33 c0 8a 44 24 08 84 c0 75 16 81 fa 80 00 00 00 72 0e 83 3d 08 13 58 00 00 74 05 e9 0b 9d } 		$a_01_1 = {66 0f ef c0 51 53 8b c1 83 e0 0f 85 c0 75 7f 8b c2 83 e2 7f c1 e8 07 74 37 8d a4 24 } 		$a_01_2 = {8b d8 f7 db 83 c3 10 2b d3 33 c0 52 8b d3 83 e2 03 74 06 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=20
 
}