rule Trojan_Win64_Lazy_ARA_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 85 20 01 00 00 48 8b 4d 00 48 8b 49 ?? 0f b6 0c 41 e8 ?? ?? ?? ?? 8b 8d 20 01 00 00 88 44 0d 10 8b 85 20 01 00 00 ff c0 89 85 20 01 00 00 eb b9 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}