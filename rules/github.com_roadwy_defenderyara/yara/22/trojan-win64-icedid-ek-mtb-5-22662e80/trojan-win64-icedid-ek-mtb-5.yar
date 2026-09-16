rule Trojan_Win64_Icedid_EK_MTB_5{
	meta:
		description = "Trojan:Win64/Icedid.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4d 75 74 65 78 57 } 		$a_01_1 = {4f 70 65 6e 53 65 6d 61 70 68 6f 72 65 57 } 		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } 		$a_01_3 = {79 75 61 67 73 66 62 76 61 79 73 66 68 6a 61 79 73 75 66 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}