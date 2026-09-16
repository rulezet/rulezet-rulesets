rule Trojan_Win64_Rozena_NR_MTB_8{
	meta:
		description = "Trojan:Win64/Rozena.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff d0 85 c0 75 07 b8 ff ff ff ff eb 75 48 8b 4d ?? 48 8d 45 ?? 48 89 44 24 ?? 48 8b 45 ?? 48 89 44 24 ?? 41 b9 00 00 00 00 41 b8 00 00 00 00 ba } 		$a_03_1 = {e9 a8 00 00 00 48 8b 55 ?? 48 8b 4d ?? 48 8d 45 ?? 48 89 44 24 ?? 41 b9 00 00 00 00 49 89 d0 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}