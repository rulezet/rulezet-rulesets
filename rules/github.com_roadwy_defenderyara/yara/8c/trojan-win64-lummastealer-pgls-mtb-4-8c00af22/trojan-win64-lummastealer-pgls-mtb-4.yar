rule Trojan_Win64_LummaStealer_PGLS_MTB_4{
	meta:
		description = "Trojan:Win64/LummaStealer.PGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 44 24 ?? 48 8b 4c 24 20 69 04 81 95 e9 d1 5b 89 c1 c1 e9 ?? 31 c1 69 c1 95 e9 d1 5b 69 5c 24 ?? 95 e9 d1 5b 31 c3 8b 6c 24 ?? 83 c5 ?? 41 ba ?? ?? ?? ?? 41 81 fa ?? ?? ?? ?? 0f 8f ?? ?? ?? ?? e9 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}