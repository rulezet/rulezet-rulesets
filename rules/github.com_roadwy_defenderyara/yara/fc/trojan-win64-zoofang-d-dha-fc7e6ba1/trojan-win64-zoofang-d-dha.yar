rule Trojan_Win64_ZooFang_D_dha{
	meta:
		description = "Trojan:Win64/ZooFang.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 0f b6 44 3a ?? 34 ?? 0f b6 c8 48 8d 45 ?? 48 83 7d ?? ?? 48 0f 47 45 ?? 66 89 0c 02 42 0f b6 44 3a ?? 34 ?? 0f b6 c8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}