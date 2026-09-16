rule Trojan_Win64_KillMBR_ARA_MTB{
	meta:
		description = "Trojan:Win64/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {5c 63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 79 7c 20 66 6f 72 6d 61 74 20 63 3a 20 2f 66 73 3a 4e 54 46 53 20 2f 71 } 		$a_80_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}