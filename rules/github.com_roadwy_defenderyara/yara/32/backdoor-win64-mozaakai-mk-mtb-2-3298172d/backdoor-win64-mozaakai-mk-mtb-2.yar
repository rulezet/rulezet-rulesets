rule Backdoor_Win64_Mozaakai_MK_MTB_2{
	meta:
		description = "Backdoor:Win64/Mozaakai.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 83 f8 [0-01] 74 [0-01] 8b 44 24 [0-01] 39 05 1b 97 02 00 90 18 8b 0d [0-04] 48 8b 44 24 [0-01] c6 04 08 [0-01] c7 44 24 [0-03] 00 00 e8 [0-04] c7 44 24 [0-03] 00 00 8b 05 [0-04] 83 c0 01 89 05 [0-04] eb } 		$a_03_1 = {8b 05 e6 d7 [0-02] 8b 0d f0 d7 90 1b 00 33 c8 48 8b 05 3b d8 90 1b 00 89 08 c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}