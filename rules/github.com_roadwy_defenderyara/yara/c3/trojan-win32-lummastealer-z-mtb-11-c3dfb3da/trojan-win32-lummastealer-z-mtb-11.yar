rule Trojan_Win32_LummaStealer_Z_MTB_11{
	meta:
		description = "Trojan:Win32/LummaStealer.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 e6 09 f2 89 57 48 01 c8 89 47 44 83 f8 08 72 39 8b 74 24 08 eb 14 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}