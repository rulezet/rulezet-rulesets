rule Backdoor_Win64_Bazarldr_MAK_MTB{
	meta:
		description = "Backdoor:Win64/Bazarldr.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be c0 48 ff c1 03 d0 69 d2 [0-02] 00 00 8b c2 c1 f8 [0-01] 33 d0 8a 01 84 c0 75 } 		$a_03_1 = {8d 0c d2 8b c1 c1 f8 [0-01] 33 c1 69 c0 [0-02] 00 00 c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}