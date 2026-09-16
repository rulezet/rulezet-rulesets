rule Trojan_Win64_IcedID_EB_MTB_11{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 75 4a 54 51 7a 71 63 72 63 42 6c 6f 56 4d } 		$a_01_1 = {4a 62 61 64 73 6a 61 73 66 6b 73 } 		$a_01_2 = {66 61 71 52 6a 47 48 62 61 79 75 66 47 55 } 		$a_01_3 = {47 65 74 4d 65 6e 75 49 74 65 6d 49 6e 66 6f 41 } 		$a_01_4 = {52 65 6c 65 61 73 65 44 43 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}