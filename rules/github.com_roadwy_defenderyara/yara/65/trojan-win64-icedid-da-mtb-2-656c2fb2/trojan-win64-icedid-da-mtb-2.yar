rule Trojan_Win64_IcedID_DA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 8b c2 49 8b d2 48 33 d1 83 e0 3f 8a c8 48 d3 ca 48 3b d7 0f 84 5b 01 } 		$a_81_1 = {61 67 76 79 6a 64 7a 79 70 6f 62 6e 73 61 72 67 73 } 		$a_81_2 = {61 71 78 77 61 78 6e 79 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3) >=16
 
}