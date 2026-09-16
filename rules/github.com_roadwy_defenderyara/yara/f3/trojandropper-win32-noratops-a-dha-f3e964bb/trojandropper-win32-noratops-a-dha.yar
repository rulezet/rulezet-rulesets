rule TrojanDropper_Win32_Noratops_A_dha{
	meta:
		description = "TrojanDropper:Win32/Noratops.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 43 54 49 54 46 5f 66 6f 72 6d 6d 6d 6d } 		$a_01_1 = {2e 00 74 00 6d 00 70 00 2c 00 5f 00 64 00 65 00 63 00 } 		$a_01_2 = {2f 00 63 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 7e 00 24 00 } 		$a_01_3 = {5c 00 43 00 54 00 49 00 54 00 46 00 20 00 66 00 6f 00 72 00 6d 00 2e 00 70 00 64 00 66 00 } 		$a_01_4 = {25 50 44 46 2d 31 2e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=100
 
}