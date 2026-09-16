rule Trojan_Win64_IcedID_AM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 55 75 70 52 45 5a 39 64 63 } 		$a_01_1 = {44 30 63 4c 68 37 33 5a 69 6b 34 } 		$a_01_2 = {47 4e 6c 50 64 44 } 		$a_01_3 = {5a 74 61 38 58 62 57 4a 79 79 6a } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}