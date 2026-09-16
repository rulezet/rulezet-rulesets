rule Trojan_Win64_Vidar_ARA_MTB{
	meta:
		description = "Trojan:Win64/Vidar.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 32 04 16 ?? 88 44 ?? ff 44 0f b6 04 ?? 48 89 ?? 48 09 ?? 48 c1 e8 20 75 a2 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}