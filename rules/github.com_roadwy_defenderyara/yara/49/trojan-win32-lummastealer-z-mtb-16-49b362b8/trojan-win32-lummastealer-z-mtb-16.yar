rule Trojan_Win32_LummaStealer_Z_MTB_16{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fd 41 80 e5 29 41 80 e2 10 45 08 ea 45 08 df 41 80 e3 29 80 e1 d6 44 08 d9 44 30 d1 41 f6 d7 41 08 cf 89 d9 20 d1 30 da 08 ca 44 89 f9 f6 d1 20 d1 f6 d2 44 20 fa 08 ca 44 08 c8 f6 d0 89 d1 20 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}