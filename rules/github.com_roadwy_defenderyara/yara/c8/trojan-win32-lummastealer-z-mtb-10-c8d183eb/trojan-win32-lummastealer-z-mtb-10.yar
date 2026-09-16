rule Trojan_Win32_LummaStealer_Z_MTB_10{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 60 08 01 b3 85 d7 34 66 85 80 b5 4a a9 2b 43 09 2a d6 47 e5 d2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}