rule Trojan_Win64_IcedID_EC_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 61 67 73 6a 64 62 61 68 73 64 6a 73 } 		$a_01_1 = {68 4a 6e 43 78 43 70 6a 64 45 47 49 54 65 75 } 		$a_01_2 = {6c 4b 6b 4b 62 63 57 69 4e 71 74 44 74 } 		$a_01_3 = {52 65 67 69 73 74 65 72 43 6c 61 73 73 45 78 57 } 		$a_01_4 = {47 65 74 46 6f 63 75 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}