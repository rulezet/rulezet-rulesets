rule Ransom_Win32_Genasom_KT_2{
	meta:
		description = "Ransom:Win32/Genasom.KT,SIGNATURE_TYPE_PEHSTR,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {d0 b4 d0 b5 d0 bd d1 8c d0 b3 d0 b8 2c 20 d0 bf d1 83 d1 82 d0 b5 d0 bc 20 d0 bf d0 b5 d1 80 d0 b5 d1 87 d0 b8 d1 81 d0 bb d0 b5 d0 bd d0 b8 d1 8f 20 d1 81 d1 83 d0 bc d0 bc d1 8b 20 0d 0a d0 b2 d0 b7 d1 8b d1 81 d0 ba d0 b0 d0 bd d0 b8 d1 8f 20 d0 bd d0 b0 20 d0 ba d0 be d1 88 d0 b5 d0 bb d0 b5 d0 ba 20 57 65 62 4d 6f 6e 65 79 20 55 } 		$a_01_1 = {42 65 68 72 69 6e 67 65 72 58 33 32 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 } 		$a_01_2 = {53 75 73 70 65 6e 64 4c 61 79 6f 75 74 00 42 65 67 69 6e 49 6e 69 74 00 73 65 74 5f 41 6e 63 68 6f 72 00 67 65 74 5f 4c 69 67 68 74 47 72 61 79 00 73 65 74 5f 42 61 63 6b 43 6f 6c 6f 72 00 } 		$a_01_3 = {8e c2 94 c2 93 c2 91 c2 92 c2 8a c2 95 c2 95 c2 88 c2 92 c2 92 c2 87 c2 8b c2 8f c2 89 c2 95 c2 88 c2 8f c2 8a 00 55 49 6e 74 33 32 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}