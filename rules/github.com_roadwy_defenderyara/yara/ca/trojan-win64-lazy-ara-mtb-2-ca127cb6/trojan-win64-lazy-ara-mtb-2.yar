rule Trojan_Win64_Lazy_ARA_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 c3 80 e3 ?? 80 cb ?? 24 ?? 30 d8 34 ?? 88 05 } 		$a_03_1 = {89 c2 80 e2 ?? 80 ca ?? 24 ?? 30 d0 34 ?? 88 05 } 		$a_01_2 = {74 65 73 74 31 32 33 31 32 33 31 32 33 31 32 33 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*3) >=5
 
}