rule Trojan_Win32_Amadey_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {49 53 4e 6d 66 56 3d 3d } 		$a_81_1 = {56 33 42 66 31 48 57 6f 62 79 74 3d } 		$a_81_2 = {4a 6a 73 72 50 6c 3d 3d } 		$a_81_3 = {52 33 4a 62 65 73 49 35 63 73 3d 3d } 		$a_81_4 = {25 75 73 65 72 61 70 70 64 61 74 61 25 5c 52 65 73 74 61 72 74 41 70 70 2e 65 78 65 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}