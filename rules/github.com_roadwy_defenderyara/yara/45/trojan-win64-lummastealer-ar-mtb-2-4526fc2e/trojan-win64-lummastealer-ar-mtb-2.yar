rule Trojan_Win64_LummaStealer_AR_MTB_2{
	meta:
		description = "Trojan:Win64/LummaStealer.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 f1 01 89 c3 30 cb 20 c3 20 c1 08 d1 89 d8 30 c8 a8 01 ba ?? ?? ?? ?? 41 0f 45 d1 f6 c1 01 89 d0 41 0f 45 c1 f6 c3 01 0f 44 c2 } 		$a_03_1 = {89 ca 80 f2 01 30 c1 34 01 89 d3 20 c3 30 d0 08 d8 89 c2 30 ca a8 01 b8 ?? ?? ?? ?? 41 0f 45 c2 f6 c1 01 41 0f 44 c2 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*8) >=18
 
}