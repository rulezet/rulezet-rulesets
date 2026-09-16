rule Trojan_Win32_LummaStealer_Z_MTB_15{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7c 24 64 89 c2 b9 03 00 00 00 87 d6 f3 a5 87 d6 8d 7c 24 70 8d 50 0c b9 01 00 00 00 87 d6 f3 66 a5 87 d6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}