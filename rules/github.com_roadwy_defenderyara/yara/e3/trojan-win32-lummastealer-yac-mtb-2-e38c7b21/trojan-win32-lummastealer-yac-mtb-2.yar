rule Trojan_Win32_LummaStealer_YAC_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 9c c0 8b 04 85 ?? ?? ?? ?? b9 42 7c b1 d1 33 0d ?? ?? ?? ?? 01 c8 40 ff e0 } 		$a_03_1 = {89 ce 21 de 01 f6 29 de 01 d6 21 ce 89 f5 81 e5 ?? ?? ?? ?? 89 f0 83 e0 02 89 f7 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}