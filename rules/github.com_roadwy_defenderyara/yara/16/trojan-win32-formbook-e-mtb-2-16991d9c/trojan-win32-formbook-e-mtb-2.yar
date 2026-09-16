rule Trojan_Win32_FormBook_E_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.E!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c1 92 ab 00 00 05 25 7f 00 00 48 f7 d3 81 e2 14 0c 01 00 f7 d1 58 b9 14 c4 00 00 4a 42 48 f7 d1 05 a2 66 00 00 41 25 8b 0a 01 00 3d b9 0a 00 00 74 06 ba 67 43 00 00 59 4b 5b 81 f1 81 f0 00 00 81 f1 b8 52 00 00 81 c1 a1 f6 00 00 c2 1b 1d } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}