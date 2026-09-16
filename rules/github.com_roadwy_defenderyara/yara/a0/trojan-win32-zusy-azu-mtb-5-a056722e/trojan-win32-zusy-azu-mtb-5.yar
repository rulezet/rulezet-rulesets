rule Trojan_Win32_Zusy_AZU_MTB_5{
	meta:
		description = "Trojan:Win32/Zusy.AZU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 cc 43 c6 45 cd 3a c6 45 ce 5c c6 45 cf 55 c6 45 d0 73 c6 45 d1 65 c6 45 d2 72 c6 45 d3 73 c6 45 d4 5c c6 45 d5 50 c6 45 d6 75 c6 45 d7 62 c6 45 d8 6c c6 45 d9 69 c6 45 da 63 c6 45 db 5c c6 45 dc 43 c6 45 dd 6f c6 45 de 4e c6 45 df 6e c6 45 e0 55 c6 45 e1 6f c6 45 e2 62 c6 45 e3 64 c6 45 e4 73 c6 45 e5 5c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}