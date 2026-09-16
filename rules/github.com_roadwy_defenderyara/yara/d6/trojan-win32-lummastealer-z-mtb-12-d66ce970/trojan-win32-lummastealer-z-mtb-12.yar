rule Trojan_Win32_LummaStealer_Z_MTB_12{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 56 48 83 c0 f8 89 46 44 83 f8 07 76 42 8b 4e 30 3b 4e 34 73 e7 8d 41 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}