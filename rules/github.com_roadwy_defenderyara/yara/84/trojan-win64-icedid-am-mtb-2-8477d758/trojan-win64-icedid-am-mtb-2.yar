rule Trojan_Win64_IcedID_AM_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 75 75 54 67 62 71 } 		$a_01_1 = {50 4a 51 6a 64 63 66 } 		$a_01_2 = {57 48 52 49 32 48 32 } 		$a_01_3 = {57 54 66 32 45 38 } 		$a_01_4 = {57 58 6d 4e 51 57 69 51 63 64 } 		$a_01_5 = {68 66 64 66 61 73 64 66 63 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}