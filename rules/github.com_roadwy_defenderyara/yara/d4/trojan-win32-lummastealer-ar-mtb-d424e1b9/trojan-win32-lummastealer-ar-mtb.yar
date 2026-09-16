rule Trojan_Win32_LummaStealer_AR_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 95 c2 88 d4 30 cc 20 e2 20 cc 88 d5 20 e5 30 d4 08 ec 30 e0 08 cc f6 d0 f6 d4 } 		$a_01_1 = {89 ca 20 e0 30 c1 80 f2 01 34 01 08 d0 34 01 08 c8 88 c1 20 e8 80 f5 01 80 f1 01 88 ea 30 ca 20 e9 20 ea 08 c1 89 d0 } 	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}