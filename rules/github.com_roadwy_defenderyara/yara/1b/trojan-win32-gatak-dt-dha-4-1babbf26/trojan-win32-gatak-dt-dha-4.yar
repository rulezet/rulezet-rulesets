rule Trojan_Win32_Gatak_DT_dha_4{
	meta:
		description = "Trojan:Win32/Gatak.DT!dha,SIGNATURE_TYPE_PEHSTR,64 00 64 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f8 00 c6 45 d8 4d c6 45 d9 70 c6 45 da 53 c6 45 db 74 c6 45 dc 61 c6 45 dd 72 c6 45 de 74 c6 45 df 50 c6 45 e0 72 c6 45 e1 6f c6 45 e2 63 c6 45 e3 65 c6 45 e4 73 c6 45 e5 73 c6 45 e6 00 } 	condition:
		((#a_01_0  & 1)*5) >=100
 
}