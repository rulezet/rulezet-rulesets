rule Trojan_Win64_LummaStealer_PGLS_MTB_3{
	meta:
		description = "Trojan:Win64/LummaStealer.PGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 94 c0 0f 95 c1 83 3d ?? ?? ?? ?? 0a 0f 9c c3 30 d9 80 f1 01 89 da 08 c2 80 f2 01 08 ca 89 c1 30 d9 20 c8 20 d9 89 c3 80 f3 01 30 c8 80 f1 01 08 d9 80 f1 01 08 c1 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}