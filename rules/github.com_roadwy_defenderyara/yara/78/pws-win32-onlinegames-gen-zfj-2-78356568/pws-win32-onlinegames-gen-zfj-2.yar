rule PWS_Win32_OnLineGames_gen_ZFJ_2{
	meta:
		description = "PWS:Win32/OnLineGames.gen!ZFJ,SIGNATURE_TYPE_PEHSTR,14 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 5d 90 c6 45 94 53 c6 45 95 68 c6 45 96 49 c6 45 97 6d c6 45 98 67 c6 45 99 56 c6 45 9a 77 c6 45 9b 3a c6 45 9c 43 c6 45 9d 50 c6 45 9e 72 c6 45 9f 65 c6 45 a0 76 c6 45 a1 69 c6 45 a2 65 c6 45 a3 77 c6 45 a4 57 c6 45 a5 6e c6 45 a6 64 88 5d a7 c6 45 b8 65 c6 45 b9 78 c6 45 ba 70 c6 45 bb 6c c6 45 bc 6f c6 45 bd 72 c6 45 be 65 c6 45 bf 72 c6 45 c0 2e c6 45 c1 65 c6 45 c2 78 c6 45 c3 65 88 5d c4 } 		$a_01_1 = {ff 75 a4 c6 45 ac 25 c6 45 ad 73 c6 45 ae 3f 50 8d 85 a0 fd ff ff 50 c6 45 af 61 c6 45 b0 63 c6 45 b1 74 c6 45 b2 69 c6 45 b3 6f c6 45 b4 6e c6 45 b5 3d c6 45 b6 64 c6 45 b7 72 c6 45 b8 6f c6 45 b9 70 c6 45 ba 6f c6 45 bb 66 c6 45 bc 66 c6 45 bd 26 c6 45 be 75 c6 45 bf 3d c6 45 c0 25 c6 45 c1 73 88 5d c2 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}