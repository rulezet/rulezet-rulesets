rule Trojan_Win64_IcedId_MG_MTB_2{
	meta:
		description = "Trojan:Win64/IcedId.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_1 = {41 4b 6f 73 75 47 55 70 } 		$a_01_2 = {41 5a 6c 52 64 55 59 62 56 4c 6e } 		$a_01_3 = {54 74 2e 64 6c 6c } 		$a_01_4 = {42 41 79 58 66 63 44 6d 63 4b } 		$a_01_5 = {43 66 4f 61 77 67 6f 6f 75 4a 66 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}