rule Trojan_Win64_IcedID_M_MTB{
	meta:
		description = "Trojan:Win64/IcedID.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 44 24 27 04 c6 44 24 28 1c 66 3b c0 74 57 80 44 24 2e 11 c6 44 24 2f 07 66 3b c0 74 2d 80 44 24 2d 39 c6 44 24 2e 11 66 3b c0 74 e2 } 		$a_01_1 = {75 61 69 73 79 64 62 76 74 61 76 73 67 68 64 6a 61 6b 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}