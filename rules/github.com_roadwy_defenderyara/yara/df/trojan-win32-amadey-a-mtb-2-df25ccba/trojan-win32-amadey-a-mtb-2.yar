rule Trojan_Win32_Amadey_A_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {44 3a 5c 4d 6b 74 6d 70 5c 4e 4c 31 5c 52 65 6c 65 61 73 65 5c 4e 4c 31 2e 70 64 62 } 		$a_81_1 = {4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } 		$a_81_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}