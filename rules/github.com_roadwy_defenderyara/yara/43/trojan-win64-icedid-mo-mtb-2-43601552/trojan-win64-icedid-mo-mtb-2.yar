rule Trojan_Win64_IcedID_MO_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 79 47 31 4f 34 2e 64 6c 6c } 		$a_01_1 = {61 77 74 75 67 68 6a 64 61 73 75 } 		$a_01_2 = {43 62 46 52 53 47 44 55 52 70 } 		$a_01_3 = {44 51 4d 42 43 78 72 78 67 6d 4b } 		$a_01_4 = {57 41 4c 76 6d 76 70 } 		$a_01_5 = {44 46 6b 48 4c 4d 62 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}