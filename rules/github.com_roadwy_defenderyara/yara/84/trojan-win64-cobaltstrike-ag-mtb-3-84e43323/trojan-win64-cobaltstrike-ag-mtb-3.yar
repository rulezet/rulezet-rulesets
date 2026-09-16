rule Trojan_Win64_Cobaltstrike_AG_MTB_3{
	meta:
		description = "Trojan:Win64/Cobaltstrike.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 04 ?? ?? ?? ?? 48 8b 4c 24 ?? 0f b6 09 33 c8 8b c1 48 8b 4c 24 ?? 88 01 8b 44 24 20 ff c0 89 44 24 20 8b 44 24 20 83 e0 07 89 44 24 20 eb } 		$a_01_1 = {52 64 76 53 65 72 76 69 63 65 4d 61 69 6e 40 40 59 41 58 50 45 41 58 30 4b 30 4b 40 5a } 	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}