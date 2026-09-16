rule Trojan_Win64_IcedID_H_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 5d 00 00 00 83 c0 08 66 3b ed 74 ba 83 c0 29 66 89 44 24 52 66 3b c0 74 00 33 c0 66 89 44 24 54 66 3b f6 74 43 b8 05 00 00 00 83 c0 2e 66 3b d2 74 27 } 		$a_01_1 = {79 67 61 73 62 64 6a 6b 62 73 79 64 75 6a 68 61 6b 73 64 61 73 64 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}