rule Backdoor_Win32_Farfli_GMC_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 31 1b 2f 99 32 41 79 00 67 4c 40 21 0e } 		$a_01_1 = {40 56 50 72 6f 74 65 63 74 } 		$a_01_2 = {5a 71 4c 32 47 41 31 4f 54 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}