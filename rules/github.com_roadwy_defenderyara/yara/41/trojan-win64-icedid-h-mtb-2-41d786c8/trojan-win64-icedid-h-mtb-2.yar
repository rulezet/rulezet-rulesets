rule Trojan_Win64_IcedID_H_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 44 24 38 66 3b d2 74 1d 44 89 4c 24 20 4c 89 44 24 18 3a f6 74 00 48 89 54 24 10 48 89 4c 24 08 66 3b f6 74 20 } 		$a_01_1 = {66 61 68 67 64 61 67 79 75 73 64 61 6a 73 64 6b 61 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}