rule Trojan_Win64_Lazy_AHI_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 89 cb 30 c3 44 08 c8 41 80 f1 ?? 80 f2 ?? 44 20 ca 08 ca 34 ?? 08 d8 89 c1 30 d1 a8 } 		$a_03_1 = {08 d0 89 ca 80 f2 ?? 20 c2 34 ?? 20 c8 08 d0 44 30 c8 89 c1 80 f1 ?? 41 20 c9 44 30 c9 } 	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}