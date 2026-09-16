rule Trojan_Win64_Cobaltstrike_DL_MTB_3{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 29 c0 8b 05 ?? ?? ?? ?? 41 29 c0 8b 05 ?? ?? ?? ?? 41 29 c0 8b 05 ?? ?? ?? ?? 41 29 c0 44 89 c0 4c 63 c0 48 8b 45 ?? 4c 01 c0 0f b6 00 31 c8 88 02 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 0f 82 } 		$a_81_1 = {6e 25 72 21 77 3f 24 2b 4f 56 77 64 76 68 35 37 24 37 41 40 33 31 54 2b 4b 4f 36 6a 4a 73 21 69 32 72 66 23 53 3c 76 6b 5e 5a 44 6a 5a 35 56 32 69 4d 33 25 6f 34 51 32 3c 36 2b 44 28 47 } 	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}