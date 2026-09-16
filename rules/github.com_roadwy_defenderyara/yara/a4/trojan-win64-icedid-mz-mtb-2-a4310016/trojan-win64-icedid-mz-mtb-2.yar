rule Trojan_Win64_IcedID_MZ_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 4f 62 6a 65 63 74 } 		$a_01_1 = {62 38 4a 7a 33 2e 64 6c 6c } 		$a_01_2 = {42 53 51 58 4c 62 64 61 } 		$a_01_3 = {47 72 32 34 47 61 66 4f 42 } 		$a_01_4 = {50 6c 4b 56 78 63 58 35 } 		$a_01_5 = {56 63 42 6e 6e 34 6b 39 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}