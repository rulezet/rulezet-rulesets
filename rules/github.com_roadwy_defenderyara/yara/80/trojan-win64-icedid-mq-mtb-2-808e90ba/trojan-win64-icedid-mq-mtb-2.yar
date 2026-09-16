rule Trojan_Win64_IcedID_MQ_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_1 = {6c 43 71 42 64 65 7a 35 76 75 2e 64 6c 6c } 		$a_01_2 = {42 58 64 41 69 78 43 6d 4b 53 } 		$a_01_3 = {48 79 4f 72 56 51 52 57 61 49 } 		$a_01_4 = {50 59 44 45 6b 6e 4f 6d 71 4e } 		$a_01_5 = {54 77 5a 48 58 52 6a 55 6f 75 46 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}