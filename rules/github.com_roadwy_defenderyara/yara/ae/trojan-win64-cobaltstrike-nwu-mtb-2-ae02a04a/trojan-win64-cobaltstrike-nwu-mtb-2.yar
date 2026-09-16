rule Trojan_Win64_CobaltStrike_NWU_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.NWU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 54 63 68 6f 75 70 69 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 54 63 68 6f 75 70 69 2e 70 64 62 } 		$a_01_1 = {41 64 64 20 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } 		$a_01_2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 44 65 66 65 6e 64 65 72 } 		$a_01_3 = {57 69 6e 45 78 65 63 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}