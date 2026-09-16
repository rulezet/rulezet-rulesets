rule Trojan_Win64_IcedID_DB_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 6b 6e 74 54 46 57 66 45 5a 45 43 72 } 		$a_01_1 = {47 61 52 6e 74 6e 62 44 50 58 53 58 68 72 46 4f 66 73 6d } 		$a_01_2 = {49 49 49 6d 78 70 70 4f 6a 70 76 52 6d 43 6b 6c 79 47 54 } 		$a_01_3 = {4b 6b 6e 63 75 48 4a 51 43 4a 43 77 42 62 6b } 		$a_01_4 = {4c 6b 62 76 4e 62 7a 77 71 57 47 61 65 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}