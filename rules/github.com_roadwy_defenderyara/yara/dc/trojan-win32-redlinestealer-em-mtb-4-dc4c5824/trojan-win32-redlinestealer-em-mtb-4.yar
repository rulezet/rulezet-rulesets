rule Trojan_Win32_RedLineStealer_EM_MTB_4{
	meta:
		description = "Trojan:Win32/RedLineStealer.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {96 4b 27 81 db 93 00 00 00 2b f7 87 d2 f7 ea 27 83 e7 62 0b ff 87 da } 		$a_01_1 = {97 f7 d8 f8 25 89 00 00 00 8b ff 93 40 2f 83 ea 45 8b c7 87 d3 } 	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*7) >=7
 
}