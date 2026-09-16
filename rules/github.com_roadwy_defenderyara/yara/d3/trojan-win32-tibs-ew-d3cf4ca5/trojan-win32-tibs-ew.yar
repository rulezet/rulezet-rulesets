rule Trojan_Win32_Tibs_EW{
	meta:
		description = "Trojan:Win32/Tibs.EW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 d0 89 c1 c3 89 eb 81 c3 10 19 00 00 89 e8 c3 83 c4 04 89 e1 89 fc 50 89 cc 39 dd 7e af c3 56 89 ee ad } 		$a_01_1 = {83 c5 02 89 ef 83 c5 02 83 c7 02 89 f9 29 e9 89 ca 81 c2 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}