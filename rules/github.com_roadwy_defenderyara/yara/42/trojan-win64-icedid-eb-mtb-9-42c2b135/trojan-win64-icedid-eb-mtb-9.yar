rule Trojan_Win64_IcedID_EB_MTB_9{
	meta:
		description = "Trojan:Win64/IcedID.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 68 48 6b 44 4f 50 41 57 44 4d } 		$a_01_1 = {50 41 69 56 68 67 44 65 79 4f 63 } 		$a_01_2 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_3 = {51 4b 67 4b 55 4e 65 73 42 6e 76 55 78 64 } 		$a_01_4 = {52 62 59 62 75 72 42 53 53 6b 50 6b 4a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}