rule Trojan_Win32_Fragtor_NF_MTB_3{
	meta:
		description = "Trojan:Win32/Fragtor.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_81_0 = {6c 69 62 79 75 67 76 38 36 2e 64 6c 6c } 		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 70 75 62 6c 75 62 5c 44 75 76 41 70 70 } 		$a_81_2 = {67 63 72 79 5f 6d 64 5f 73 65 74 6b 65 79 } 		$a_81_3 = {54 72 69 61 6c 45 78 70 69 72 65 } 		$a_81_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } 	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1) >=15
 
}