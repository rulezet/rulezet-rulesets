rule Trojan_Win64_IcedID_FB_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.FB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a c0 74 d8 44 89 4c 24 20 4c 89 44 24 18 66 3b d2 74 12 83 44 24 40 08 c7 44 24 44 1b 00 00 00 66 3b f6 74 a5 48 89 54 24 10 48 89 4c 24 08 3a e4 74 00 48 81 ec 68 02 00 00 c7 44 24 30 6e 00 00 00 3a ed 0f 84 4c ff ff ff } 		$a_01_1 = {6e 74 61 67 73 68 6a 6a 61 73 68 67 64 61 61 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}