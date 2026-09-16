rule PWS_Win32_OnLineGames_gen_ZFJ{
	meta:
		description = "PWS:Win32/OnLineGames.gen!ZFJ,SIGNATURE_TYPE_PEHSTR,14 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 c6 45 e8 4c c6 45 e9 61 c6 45 ea 75 c6 45 eb 6e c6 45 ec 63 c6 45 ed 68 c6 45 ee 2e c6 45 ef 65 c6 45 f0 78 c6 45 f1 65 c6 45 d4 53 c6 45 d5 65 c6 45 d6 44 c6 45 d7 65 c6 45 d8 62 c6 45 d9 75 c6 45 da 67 c6 45 db 50 c6 45 dc 72 c6 45 dd 69 c6 45 de 76 c6 45 df 69 c6 45 e0 6c c6 45 e1 65 c6 45 e2 67 c6 45 e3 65 c6 45 f4 47 c6 45 f5 61 c6 45 f6 6d c6 45 f7 65 c6 45 f8 2e c6 45 f9 65 c6 45 fa 78 c6 45 fb 65 e8 } 		$a_01_1 = {53 56 57 c6 45 e4 73 c6 45 e5 66 c6 45 e6 63 c6 45 e7 5f c6 45 e8 6f c6 45 e9 73 c6 45 ea 2e c6 45 eb 64 c6 45 ec 6c c6 45 ed 6c 80 65 ee 00 68 04 01 00 00 6a 00 68 c4 45 40 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}