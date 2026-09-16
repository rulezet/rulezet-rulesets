rule Trojan_Win32_LummaStealer_Z_MTB_13{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 77 28 73 25 56 ff 77 2c ff 77 20 ff 71 34 ff 51 30 83 c4 10 85 c0 0f 84 7c 02 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}