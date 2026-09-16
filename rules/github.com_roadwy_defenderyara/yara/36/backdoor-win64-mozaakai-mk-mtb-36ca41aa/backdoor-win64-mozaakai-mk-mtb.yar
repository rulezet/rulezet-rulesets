rule Backdoor_Win64_Mozaakai_MK_MTB{
	meta:
		description = "Backdoor:Win64/Mozaakai.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 05 07 19 00 00 89 c1 80 f1 [0-01] 20 c1 89 c8 b2 [0-01] 20 d0 30 d1 08 c1 88 0d f0 [0-03] b8 [0-04] 45 31 ed e9 } 		$a_03_1 = {8b 4c 84 48 89 ca f7 d2 81 e2 [0-04] 81 e1 [0-04] 09 d1 81 f1 [0-04] 89 [0-03] 48 85 c0 b8 [0-02] 00 00 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}