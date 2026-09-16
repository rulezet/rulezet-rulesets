rule Trojan_Win32_DllInject_MB_MTB_3{
	meta:
		description = "Trojan:Win32/DllInject.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 0a d8 e9 d8 e1 d8 ec d8 df 89 11 eb 10 d8 d3 d8 c3 d8 cf 88 0e d8 d1 d8 ce d8 d9 89 0e eb 6a d8 d9 d8 e6 d8 e3 d8 d4 d8 d5 d8 db 8a 0b d8 e0 } 		$a_01_1 = {89 0b d8 dd d8 cb d8 c5 89 10 d8 df d8 cf d8 e7 d8 d3 d8 dc d8 e2 d8 c1 d8 db d8 d9 d8 df 89 0a d8 d7 d8 d2 d8 e1 d8 eb d8 cb d8 d3 d8 ce d8 e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}