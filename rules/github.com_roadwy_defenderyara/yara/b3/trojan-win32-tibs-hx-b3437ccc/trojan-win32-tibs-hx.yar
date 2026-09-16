rule Trojan_Win32_Tibs_HX{
	meta:
		description = "Trojan:Win32/Tibs.HX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c3 58 59 5a 69 db 00 00 01 00 01 df 83 ef 01 83 ef 01 83 ef 02 81 ef 00 70 00 00 81 ef 00 60 00 00 81 ef 00 30 00 00 e2 b7 c3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}