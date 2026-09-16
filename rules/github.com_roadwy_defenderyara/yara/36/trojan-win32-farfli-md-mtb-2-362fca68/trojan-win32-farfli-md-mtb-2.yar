rule Trojan_Win32_Farfli_MD_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {c6 45 dd 59 c6 45 de 53 c6 45 df 54 c6 45 e0 45 c6 45 e1 4d c6 45 e2 5c c6 45 e3 43 c6 45 e4 75 c6 45 e5 72 c6 45 e6 72 c6 45 e7 65 c6 45 e8 6e c6 45 e9 74 c6 45 ea 43 c6 45 eb 6f c6 45 ec 6e c6 45 ed 74 c6 45 ee 72 c6 45 ef 6f c6 45 f0 6c c6 45 f1 53 c6 45 f2 65 c6 45 f3 74 c6 45 f4 5c c6 45 f5 53 c6 45 f6 65 c6 45 f7 72 c6 45 f8 76 c6 45 f9 69 c6 45 fa 63 c6 45 fb 65 c6 45 fc 73 c6 45 fd 5c 88 ?? fe } 		$a_81_1 = {53 65 72 70 69 65 69 } 	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}