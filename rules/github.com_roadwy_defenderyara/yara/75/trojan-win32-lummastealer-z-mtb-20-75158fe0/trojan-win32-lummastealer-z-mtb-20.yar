rule Trojan_Win32_LummaStealer_Z_MTB_20{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 30 c7 40 88 f0 34 ff 45 88 f4 41 80 f4 ff 41 88 fd 41 80 f5 00 88 c1 80 e1 00 44 20 ee 44 88 e2 80 e2 00 45 20 ee 40 08 f1 44 08 f2 30 d1 44 08 e0 34 ff 41 80 cd 00 44 20 e8 08 c1 40 88 f8 34 00 44 88 fa 80 f2 ff 40 88 fe 40 80 f6 01 41 88 c6 41 80 e6 ff 41 88 f4 41 80 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}