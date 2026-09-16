rule Backdoor_BAT_Nanocore_MTB_5{
	meta:
		description = "Backdoor:BAT/Nanocore!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 65 5a 65 72 30 2e 50 72 6f 70 65 72 74 69 65 73 } 		$a_01_1 = {52 65 5a 65 72 30 56 32 } 		$a_01_2 = {53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 } 		$a_01_3 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } 		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}