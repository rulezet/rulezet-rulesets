rule Trojan_Win64_IcedID_MA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_01_1 = {31 74 33 45 6f 38 2e 64 6c 6c } 		$a_01_2 = {44 6b 73 50 70 42 4b 75 71 } 		$a_01_3 = {4c 51 79 68 73 43 64 6a 6c } 		$a_01_4 = {53 51 63 63 44 6d 4a 6c 68 45 } 		$a_01_5 = {56 6f 73 51 6c 42 72 58 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}