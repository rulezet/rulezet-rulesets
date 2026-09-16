rule Trojan_Win32_LummaStealer_ZHK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZHK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 78 87 b6 9f 54 b7 7d a9 3d } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}