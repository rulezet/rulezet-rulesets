rule Trojan_Win64_Icedid_MK_MTB_4{
	meta:
		description = "Trojan:Win64/Icedid.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 44 6e 62 2e 64 6c 6c } 		$a_01_1 = {42 68 30 31 32 56 4c 4a 43 30 7a } 		$a_01_2 = {43 68 41 78 54 6d 56 61 4c } 		$a_01_3 = {44 30 65 7a 77 51 32 6b 58 50 } 		$a_01_4 = {44 35 46 66 42 51 49 57 44 7a } 		$a_01_5 = {4b 6e 79 79 58 47 4c 49 72 32 59 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}