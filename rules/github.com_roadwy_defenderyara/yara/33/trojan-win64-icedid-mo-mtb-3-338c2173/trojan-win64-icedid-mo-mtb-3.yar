rule Trojan_Win64_IcedID_MO_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 68 61 6e 64 61 68 79 67 73 74 64 67 61 68 75 69 73 6a 64 6a 6e 73 75 61 79 73 } 		$a_01_1 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } 		$a_01_2 = {43 72 65 61 74 65 45 76 65 6e 74 41 } 		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}