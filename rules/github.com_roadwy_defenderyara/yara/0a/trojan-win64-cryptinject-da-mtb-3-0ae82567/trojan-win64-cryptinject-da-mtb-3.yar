rule Trojan_Win64_CryptInject_DA_MTB_3{
	meta:
		description = "Trojan:Win64/CryptInject.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 8b d8 8b c3 41 2b c3 66 89 44 24 ?? 8b 44 24 ?? 83 c0 ?? 89 44 24 ?? 0f b7 54 24 ?? 8b 44 24 ?? c1 e8 ?? 8b 4c 24 ?? c1 e1 ?? 0b c1 8b ca 03 c8 8b 44 24 ?? 33 c1 89 44 24 ?? eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}