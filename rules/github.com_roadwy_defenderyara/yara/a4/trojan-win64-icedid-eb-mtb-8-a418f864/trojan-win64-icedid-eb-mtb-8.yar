rule Trojan_Win64_IcedID_EB_MTB_8{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 6b 61 6a 64 73 61 73 64 } 		$a_01_1 = {48 69 64 65 43 6f 69 6e } 		$a_01_2 = {63 6f 6f 6b 69 65 58 } 		$a_01_3 = {6f 66 66 6c 69 6e 65 69 63 } 		$a_01_4 = {65 6d 61 69 6c 7c 73 65 4c 6f 61 64 69 6e 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}