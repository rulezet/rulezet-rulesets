rule Trojan_Win64_LummaStealer_PGLS_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.PGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 f8 c1 e8 0d 31 f8 69 c0 ?? ?? ?? ?? 89 c6 c1 ee ?? 31 c6 48 8b 4c 24 ?? 48 31 e1 e8 ?? ?? ?? ?? 89 f0 48 83 c4 ?? 5b 5d 5f 5e } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}