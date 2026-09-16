rule Trojan_Win32_LummaStealer_KKC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.KKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 ce 83 e6 f5 89 cf 83 e7 0a 83 c9 0a 0f af cf 83 f7 0a 0f af fe 0f be d2 01 ca 8d 0c 17 83 c1 d0 0f b6 50 01 40 89 d6 83 c6 d0 83 fe 0a } 	condition:
		((#a_01_0  & 1)*20) >=20
 
}