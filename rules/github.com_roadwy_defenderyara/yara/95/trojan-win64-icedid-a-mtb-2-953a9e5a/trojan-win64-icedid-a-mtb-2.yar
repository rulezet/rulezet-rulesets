rule Trojan_Win64_IcedID_A_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 68 70 58 35 53 51 44 39 30 57 78 } 		$a_01_1 = {55 5a 59 68 59 57 66 4a } 		$a_01_2 = {56 4f 61 46 73 59 38 50 4e } 		$a_01_3 = {66 57 69 4f 51 62 46 6b 37 } 		$a_01_4 = {6c 6b 43 38 78 6f 6f 71 5a 76 72 74 62 51 79 4a } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}