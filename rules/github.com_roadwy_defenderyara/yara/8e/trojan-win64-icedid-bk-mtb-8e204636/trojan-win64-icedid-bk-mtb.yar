rule Trojan_Win64_IcedID_BK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 6e 76 44 76 68 } 		$a_01_1 = {4c 4b 67 6b 49 34 49 63 } 		$a_01_2 = {4d 41 53 30 77 58 36 30 54 44 36 } 		$a_01_3 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_4 = {59 77 49 6a 72 47 70 73 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}