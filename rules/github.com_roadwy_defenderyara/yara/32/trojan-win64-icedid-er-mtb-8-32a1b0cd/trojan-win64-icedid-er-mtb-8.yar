rule Trojan_Win64_Icedid_ER_MTB_8{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 67 68 63 67 78 61 73 68 66 67 66 73 66 67 64 66 } 		$a_01_1 = {48 76 47 34 58 45 39 70 4e 79 69 6c 4d 4c 38 77 } 		$a_01_2 = {4d 62 31 52 4f 4c 62 6d 36 } 		$a_01_3 = {54 32 65 44 33 61 77 6f 42 7a 41 43 43 } 		$a_01_4 = {55 36 6b 78 4b 4a 42 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}