rule Trojan_Win32_RedLine_BR_MTB_2{
	meta:
		description = "Trojan:Win32/RedLine.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e7 cd c6 45 e8 46 c6 45 e9 90 c6 45 ea ee c6 45 eb 94 c6 45 ec 63 c6 45 ed bb c6 45 ee 0a c6 45 ef c0 c6 45 f0 9a c6 45 f1 50 c6 45 f2 f1 c6 45 f3 a9 c6 45 f4 a9 c6 45 f5 b0 c6 45 f6 69 c6 45 f7 1d c6 45 f8 85 c6 45 f9 04 c6 45 fa 58 c6 45 fb 9d 6a 40 68 00 30 00 00 68 00 00 a0 00 6a 00 ff 15 } 		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}