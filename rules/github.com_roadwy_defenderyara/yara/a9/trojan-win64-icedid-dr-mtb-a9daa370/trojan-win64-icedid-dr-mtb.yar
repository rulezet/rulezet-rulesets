rule Trojan_Win64_IcedID_DR_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_00_0 = {8d 50 ff 0f af d0 89 d0 83 f0 fe 85 d0 0f 94 c2 0f 94 44 24 06 41 b9 ab d8 35 48 41 b8 a0 2a 8a 08 b8 a0 2a 8a 08 41 0f 44 c1 83 f9 0a 0f 9c 44 24 } 		$a_81_1 = {53 73 78 6c 79 6b 73 6d 55 70 65 64 70 66 6a 74 62 4d 6d 78 74 79 6b 6a 63 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3) >=13
 
}