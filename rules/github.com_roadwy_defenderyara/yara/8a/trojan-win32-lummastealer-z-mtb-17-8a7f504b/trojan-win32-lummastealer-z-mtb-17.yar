rule Trojan_Win32_LummaStealer_Z_MTB_17{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 63 52 3c 4d 03 c2 4d 8b d0 4c 89 55 b8 4c 89 45 b0 45 33 c9 66 41 81 7a 18 0b 02 41 0f 94 c1 44 89 4d ac 45 85 c9 4d 8b d8 4d 0f 45 da 4c 89 5d a0 b9 60 00 00 00 89 4d 9c bb 18 00 00 00 48 63 c9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}