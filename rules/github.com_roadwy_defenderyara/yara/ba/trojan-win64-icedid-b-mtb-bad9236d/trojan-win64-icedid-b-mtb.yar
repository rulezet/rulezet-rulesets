rule Trojan_Win64_IcedID_B_MTB{
	meta:
		description = "Trojan:Win64/IcedID.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 57 71 76 48 2e 64 6c 6c } 		$a_01_1 = {48 56 4d 43 7a 4f 5a 56 6d 41 78 4b 34 6f 61 66 4e 74 } 		$a_01_2 = {72 6d 63 6b 36 79 6e 77 79 66 59 34 4e 36 49 49 6e 45 42 } 		$a_01_3 = {4c 79 32 46 6b 33 6a 46 36 70 66 62 50 62 4c 50 63 6d 30 59 6c 4c } 		$a_01_4 = {4d 32 7a 35 69 6e 45 38 65 57 68 52 37 31 4a 6c 37 32 36 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}