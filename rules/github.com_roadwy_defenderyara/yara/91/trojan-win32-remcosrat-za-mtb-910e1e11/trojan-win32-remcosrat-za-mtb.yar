rule Trojan_Win32_RemcosRAT_ZA_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {52 65 6d 63 6f 73 20 76 } 		$a_81_1 = {25 30 32 69 3a 25 30 32 69 3a 25 30 32 69 } 		$a_81_2 = {52 65 6d 63 6f 73 20 41 67 65 6e 74 20 69 6e 69 74 69 61 6c 69 7a 65 64 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}