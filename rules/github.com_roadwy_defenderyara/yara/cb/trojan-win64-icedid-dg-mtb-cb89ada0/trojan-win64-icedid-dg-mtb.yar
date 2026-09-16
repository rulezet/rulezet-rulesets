rule Trojan_Win64_IcedID_DG_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_00_0 = {0f 94 c2 0f 94 44 24 06 41 b9 ca 48 06 3d 41 b8 ba d4 b5 2d b8 ba d4 b5 2d 41 0f 44 c1 83 f9 0a 0f 9c 44 24 07 0f 9c c1 41 0f 4d c0 30 d1 41 0f 45 c1 } 		$a_81_1 = {4a 74 6d 78 72 64 70 6a 72 6f 55 61 69 62 72 77 6d } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3) >=13
 
}