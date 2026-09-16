rule Trojan_Win64_IcedID_ML_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 4f 62 6a 65 63 74 } 		$a_01_1 = {56 4d 70 42 72 4b 2e 64 6c 6c } 		$a_01_2 = {41 4d 66 46 43 6c 47 72 58 6b 59 } 		$a_01_3 = {42 58 6f 62 59 76 50 46 6e 71 75 } 		$a_01_4 = {44 4e 71 72 5a 73 48 56 71 66 } 		$a_01_5 = {50 52 6f 72 41 73 72 53 77 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}