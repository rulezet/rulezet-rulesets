rule Trojan_Win64_IcedID_EN_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 75 43 6a 39 68 32 39 56 57 61 6d 44 4d } 		$a_01_1 = {4a 77 5a 6c 42 52 39 45 77 72 4e 6a 4f 4d } 		$a_01_2 = {4b 72 4c 7a 59 45 51 7a 38 67 48 77 } 		$a_01_3 = {52 51 73 6f 74 55 45 69 6b 39 57 72 59 4f 30 } 		$a_01_4 = {54 35 42 4d 64 73 54 31 57 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}