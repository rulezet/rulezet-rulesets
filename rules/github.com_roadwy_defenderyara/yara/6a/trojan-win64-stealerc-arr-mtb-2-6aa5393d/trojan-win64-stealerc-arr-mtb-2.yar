rule Trojan_Win64_StealerC_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/StealerC.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 89 f8 48 8d bc 24 ?? ?? ?? ?? 49 89 c1 31 c0 f3 48 ab 31 c9 31 ff 41 ba } 		$a_03_1 = {49 f7 e5 4c 01 ea 48 d1 da 48 c1 ea ?? 48 89 d0 48 c1 e2 ?? 48 29 c2 4c 89 e8 49 29 d5 } 	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}