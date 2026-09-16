rule Trojan_Win64_IcedID_MC_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 61 68 67 64 61 67 79 75 73 64 61 6a 73 64 6b 61 73 } 		$a_01_1 = {44 4b 35 64 6a 57 43 } 		$a_01_2 = {44 4f 68 45 4d 50 63 41 76 } 		$a_01_3 = {51 4d 59 61 5a 4e 38 } 		$a_01_4 = {51 52 49 74 77 4a 66 6d } 		$a_01_5 = {55 69 73 47 31 74 61 4d } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}