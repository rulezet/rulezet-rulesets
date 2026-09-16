rule Trojan_Win32_Spynoon_AVM_MTB_2{
	meta:
		description = "Trojan:Win32/Spynoon.AVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 72 65 61 74 65 46 69 6c 65 57 } 		$a_81_1 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } 		$a_81_2 = {44 65 62 75 67 42 72 65 61 6b } 		$a_81_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_81_4 = {48 79 76 6b 66 63 6f 72 66 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}