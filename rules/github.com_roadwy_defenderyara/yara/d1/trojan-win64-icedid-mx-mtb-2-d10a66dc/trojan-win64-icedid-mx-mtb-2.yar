rule Trojan_Win64_IcedID_MX_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 4f 62 6a 65 63 74 } 		$a_01_1 = {44 74 35 72 65 2e 64 6c 6c } 		$a_01_2 = {4d 51 6a 50 64 73 57 57 } 		$a_01_3 = {50 64 73 31 35 56 38 52 6e 44 } 		$a_01_4 = {55 6e 43 58 35 62 36 51 } 		$a_01_5 = {58 4e 30 6e 4c 6e 36 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}