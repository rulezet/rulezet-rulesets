rule Trojan_Win64_IcedID_FB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 77 75 69 6a 6b 61 6d 64 73 6a 75 69 6a 61 } 		$a_01_1 = {66 54 6d 76 41 44 4b 51 } 		$a_01_2 = {67 39 58 63 36 6f 73 39 4b 4c } 		$a_01_3 = {69 4e 38 73 4d 38 74 } 		$a_01_4 = {6c 61 75 30 32 73 31 37 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}