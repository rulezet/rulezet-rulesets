rule Trojan_Win64_KillMBR_ARA_MTB_2{
	meta:
		description = "Trojan:Win64/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 20 72 65 67 20 64 65 6c 65 74 65 20 48 4b 43 52 2f 2a } 		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 66 69 20 22 70 69 64 20 6e 65 20 31 } 		$a_01_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}