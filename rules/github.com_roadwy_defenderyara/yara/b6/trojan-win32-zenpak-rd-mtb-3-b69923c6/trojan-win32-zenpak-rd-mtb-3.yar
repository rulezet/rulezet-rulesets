rule Trojan_Win32_Zenpak_RD_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 d1 e9 ba 93 24 49 92 89 [0-06] 89 c8 f7 e2 c1 ea 02 6b c2 0e 8b [0-06] 29 c1 89 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}