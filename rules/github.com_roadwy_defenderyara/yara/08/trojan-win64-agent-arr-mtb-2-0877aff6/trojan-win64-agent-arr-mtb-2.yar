rule Trojan_Win64_Agent_ARR_MTB_2{
	meta:
		description = "Trojan:Win64/Agent.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 8d 43 01 43 30 4c 10 ff 4c 8b df c1 ea ?? 8d 0c 92 03 c9 } 		$a_81_1 = {7a 66 7c 31 3a 6c 63 7c 31 3a 64 64 7c 31 3a 33 74 7c 30 38 3a 33 6f 7c 31 2e 30 2e 30 2e 37 32 31 3a 33 70 7c 31 3a 32 74 7c 38 38 38 38 3a 32 6f 7c 31 2e 30 2e 30 2e 37 32 31 3a 32 70 7c 31 3a 31 74 7c 36 36 36 36 3a 31 6f 7c 31 2e 30 2e 30 2e 37 32 31 3a 31 70 7c } 	condition:
		((#a_03_0  & 1)*12+(#a_81_1  & 1)*8) >=20
 
}