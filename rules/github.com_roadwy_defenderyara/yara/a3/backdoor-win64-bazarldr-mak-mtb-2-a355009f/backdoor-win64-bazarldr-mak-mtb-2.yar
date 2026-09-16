rule Backdoor_Win64_Bazarldr_MAK_MTB_2{
	meta:
		description = "Backdoor:Win64/Bazarldr.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a c1 02 85 [0-04] 30 84 0d [0-04] 48 03 cf 48 83 f9 [0-01] 72 } 		$a_03_1 = {02 c8 30 4c 04 [0-01] 49 03 c6 48 83 f8 [0-01] 73 06 8a 4c 24 [0-01] eb } 		$a_03_2 = {8a 44 24 20 02 c1 30 44 0c [0-01] 49 03 ce 48 83 f9 [0-01] 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}