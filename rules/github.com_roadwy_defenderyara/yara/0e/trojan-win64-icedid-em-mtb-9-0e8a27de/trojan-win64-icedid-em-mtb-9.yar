rule Trojan_Win64_IcedID_EM_MTB_9{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 66 3b f6 74 d4 83 c0 62 66 89 44 24 34 3a e4 74 00 b8 54 00 00 00 83 c0 0f eb cc 48 83 ec 68 } 		$a_01_1 = {66 75 61 64 73 79 67 75 61 73 67 64 75 68 61 69 73 75 64 6a 79 75 61 67 73 64 75 61 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}