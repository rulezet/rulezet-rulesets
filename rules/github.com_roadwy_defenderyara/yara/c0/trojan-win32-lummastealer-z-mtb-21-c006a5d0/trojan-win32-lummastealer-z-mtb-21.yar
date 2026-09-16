rule Trojan_Win32_LummaStealer_Z_MTB_21{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3c af c6 43 3d c1 c6 43 3e e0 c6 43 3f c7 c6 43 40 8c c6 43 41 c5 c6 43 42 ab c6 43 43 cb c6 43 44 a6 c6 43 45 c9 c6 43 46 a3 c6 43 47 cf c6 43 48 5b c6 43 49 cd c6 43 4a b0 c6 43 4b f3 c6 43 4c 9a c6 43 4d f1 c6 43 4e 61 c6 43 4f f7 c6 43 50 64 c6 43 51 f5 c6 43 52 9f c6 43 53 fb c6 43 54 65 c6 43 55 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}