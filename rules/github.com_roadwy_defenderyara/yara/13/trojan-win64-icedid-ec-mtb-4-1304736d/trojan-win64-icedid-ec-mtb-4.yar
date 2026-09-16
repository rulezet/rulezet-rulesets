rule Trojan_Win64_IcedID_EC_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 79 61 73 62 64 68 6e 61 68 73 64 79 75 61 6a 73 64 6b 61 } 		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 		$a_01_2 = {78 63 61 6e 65 73 69 35 66 65 72 73 38 6c 6f 70 64 79 74 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}