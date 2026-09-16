rule Worm_Win32_QQnof_A_2{
	meta:
		description = "Worm:Win32/QQnof.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4e 20 8b 3d a8 21 40 00 6a 00 6a 64 68 d8 00 00 00 51 ff d7 8b 56 20 6a 00 6a 64 68 cf 00 00 00 52 ff d7 } 		$a_01_1 = {62 69 61 6f 6a 69 00 00 4e 6f 74 69 66 79 57 6e 64 00 00 00 d6 d8 c6 f4 c7 b0 b6 d4 b8 c3 cf ee b2 c9 d3 c3 cf e0 cd ac b2 d9 d7 f7 2c b2 bb d4 d9 bd f8 d0 d0 cc e1 ca be 00 00 00 b2 a2 bd ab c6 e4 bc d3 c8 eb d0 c5 c8 ce b2 e5 bc fe c1 d0 b1 ed } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}