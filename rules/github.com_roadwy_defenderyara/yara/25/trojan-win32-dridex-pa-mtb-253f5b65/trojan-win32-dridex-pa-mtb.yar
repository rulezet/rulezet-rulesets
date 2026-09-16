rule Trojan_Win32_Dridex_PA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {45 53 54 41 50 50 50 65 78 65 } 		$a_81_1 = {51 44 64 65 66 61 75 6c 74 73 } 		$a_81_2 = {6e 75 6d 62 65 72 74 68 65 6d } 		$a_81_3 = {46 47 45 52 4e 2e 70 64 62 } 		$a_81_4 = {4f 72 61 63 6c 65 20 43 6f 72 70 6f 72 61 74 69 6f 6e } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}