rule Trojan_Win64_Androm_SX_MTB{
	meta:
		description = "Trojan:Win64/Androm.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 04 41 89 44 24 ?? 8b 04 24 99 b9 6d 00 00 00 f7 f9 8b c2 05 ?? ?? ?? ?? 8b 4c 24 ?? 33 c8 8b c1 48 63 0c 24 } 		$a_03_1 = {8b 44 24 34 ff c0 89 44 24 34 83 7c 24 34 ?? 7d 23 8b 44 24 24 c1 e0 ?? 8b 4c 24 24 c1 e9 ?? 0b c1 89 44 24 24 8b 44 24 24 35 ?? ?? ?? ?? 89 44 24 24 eb cc } 	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}