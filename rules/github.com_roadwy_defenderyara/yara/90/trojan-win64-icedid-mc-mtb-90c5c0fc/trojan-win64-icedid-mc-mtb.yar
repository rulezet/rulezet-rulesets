rule Trojan_Win64_IcedID_MC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_1 = {41 31 6e 63 5a 43 37 4f } 		$a_01_2 = {42 71 44 6b 57 78 } 		$a_01_3 = {44 6b 52 58 4e 6d 67 4d 72 47 } 		$a_01_4 = {4b 72 50 33 73 63 66 } 		$a_01_5 = {50 54 4f 35 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}