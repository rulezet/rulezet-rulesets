rule Trojan_Win64_ClipBanker_DG_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 83 ec 30 48 8b f9 49 8b f0 48 8b 49 10 4c 8b 47 18 49 8b c0 48 2b c1 48 3b f0 77 3f 48 89 5c 24 40 48 8d 04 31 48 89 47 10 48 8b c7 49 83 f8 10 72 03 } 		$a_81_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 43 6c 69 70 70 65 72 } 		$a_81_2 = {42 54 43 20 43 6c 69 70 70 65 72 2e 70 64 62 } 		$a_81_3 = {62 69 74 63 6f 69 6e 63 61 73 68 7c 62 63 68 72 65 67 7c 62 63 68 74 65 73 74 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}