rule Trojan_Win32_GhostRat_INS_MTB{
	meta:
		description = "Trojan:Win32/GhostRat.INS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {42 75 79 42 6f 6f 6b 2e 64 61 74 } 		$a_81_1 = {33 38 2e 34 36 2e 31 30 2e 39 30 } 		$a_81_2 = {44 6b 63 73 6b 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}