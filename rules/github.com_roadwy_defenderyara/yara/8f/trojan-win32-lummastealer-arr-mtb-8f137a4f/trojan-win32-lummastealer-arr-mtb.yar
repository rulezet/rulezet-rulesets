rule Trojan_Win32_LummaStealer_ARR_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {01 ca 83 f0 ?? 21 c8 01 c0 29 c2 89 54 24 } 		$a_01_1 = {89 c1 01 d1 21 d0 01 c0 89 ca 31 c2 f7 d0 21 c1 } 		$a_03_2 = {89 d6 f7 de 8d b4 30 ?? ?? ?? ?? 29 d0 8d 84 01 ?? ?? ?? ?? 21 ce 01 f6 29 f0 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3+(#a_03_2  & 1)*2) >=10
 
}