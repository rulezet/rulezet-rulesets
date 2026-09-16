rule Trojan_Win32_LummaStealer_Z_MTB_9{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 74 05 83 f8 2e 75 01 } 		$a_01_1 = {3d 74 05 83 f9 2e 75 01 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}