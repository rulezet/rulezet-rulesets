rule Trojan_Win64_IcedID_MJ_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_1 = {4a 4d 77 71 2e 64 6c 6c } 		$a_01_2 = {42 4c 67 53 5a 6e 4a 47 68 } 		$a_01_3 = {43 4b 4b 4f 4c 36 41 59 66 62 } 		$a_01_4 = {57 4c 73 51 62 78 4b 31 35 } 		$a_01_5 = {64 4b 69 33 42 54 59 38 4d 33 76 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}