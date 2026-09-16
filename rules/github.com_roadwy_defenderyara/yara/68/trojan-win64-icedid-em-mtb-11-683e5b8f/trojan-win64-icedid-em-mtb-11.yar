rule Trojan_Win64_IcedID_EM_MTB_11{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 5a 44 69 52 64 4c 49 67 6d 44 74 76 57 6e } 		$a_01_1 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_2 = {52 73 6e 67 6b 47 6d 4b 52 49 52 57 45 43 5a 73 70 6c 4d 79 6d } 		$a_01_3 = {53 63 58 6f 56 41 72 72 58 65 6a 43 48 } 		$a_01_4 = {58 64 75 47 48 4f 58 46 4c 59 4c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}