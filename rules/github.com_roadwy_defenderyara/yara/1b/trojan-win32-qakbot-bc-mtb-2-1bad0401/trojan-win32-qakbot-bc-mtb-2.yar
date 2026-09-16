rule Trojan_Win32_QakBot_BC_MTB_2{
	meta:
		description = "Trojan:Win32/QakBot.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 00 e8 [0-04] 2b d8 a1 [0-04] 33 18 89 1d [0-04] 6a 00 e8 [0-04] 8b d8 03 1d [0-04] 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 03 d8 a1 [0-04] 89 18 6a 00 e8 [0-04] 8b d8 a1 [0-04] 83 c0 04 03 d8 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}