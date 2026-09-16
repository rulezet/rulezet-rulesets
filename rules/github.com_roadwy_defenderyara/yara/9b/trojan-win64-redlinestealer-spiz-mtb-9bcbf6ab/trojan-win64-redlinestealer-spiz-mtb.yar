rule Trojan_Win64_RedLineStealer_SPIZ_MTB{
	meta:
		description = "Trojan:Win64/RedLineStealer.SPIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {47 71 67 57 7a 64 } 		$a_81_1 = {77 6f 72 6b 65 72 5f 46 44 68 76 77 63 } 		$a_81_2 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 } 		$a_81_3 = {70 72 6f 63 65 78 70 2e 65 78 65 } 		$a_81_4 = {78 36 34 64 62 67 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}