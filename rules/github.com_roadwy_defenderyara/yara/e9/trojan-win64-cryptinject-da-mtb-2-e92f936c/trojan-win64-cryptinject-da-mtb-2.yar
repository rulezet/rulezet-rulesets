rule Trojan_Win64_CryptInject_DA_MTB_2{
	meta:
		description = "Trojan:Win64/CryptInject.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 fe c1 49 ff c3 45 0f b6 c9 42 8b 7c 8e ?? 44 02 d7 45 0f b6 d2 42 8b 4c 96 ?? 42 89 4c 8e ?? 40 02 cf 42 89 7c 96 ?? 0f b6 c1 0f b6 4c 86 ?? 41 30 4b ?? 48 ff cb 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}