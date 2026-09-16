rule Trojan_Win32_DllInject_MA_MTB_2{
	meta:
		description = "Trojan:Win32/DllInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 56 d8 e7 d8 d8 d8 c9 d8 e2 d8 ed 8a 0a d8 cd d8 c1 8a 0e d8 c3 d8 df d8 e6 8a 12 d8 cd d8 c2 d8 c8 d8 e1 d8 df d8 ea d8 e2 d8 d1 d8 ce d8 e1 } 		$a_01_1 = {d8 da d8 c7 d8 c4 8a 13 eb 42 d8 cf d8 c8 d8 c6 d8 c5 d8 e7 d8 dd d8 d1 d8 eb d8 c8 88 0c d8 e6 d8 c8 89 11 d8 c6 d8 d1 d8 dc 88 0f d8 cb d8 c0 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}