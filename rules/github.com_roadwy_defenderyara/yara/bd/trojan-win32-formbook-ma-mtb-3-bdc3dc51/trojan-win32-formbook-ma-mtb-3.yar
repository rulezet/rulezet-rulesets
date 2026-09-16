rule Trojan_Win32_Formbook_MA_MTB_3{
	meta:
		description = "Trojan:Win32/Formbook.MA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c3 de 41 00 00 b9 de 89 00 00 48 40 81 c1 2a b0 00 00 81 e1 51 57 00 00 c2 e3 ba f7 d2 81 f2 34 12 01 00 4a 2d ad 38 00 00 4b 42 5b 81 c2 bc 5b 01 00 3d c9 55 00 00 74 0d } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}