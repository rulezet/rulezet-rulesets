rule Trojan_Win64_IcedID_EM_MTB_10{
	meta:
		description = "Trojan:Win64/IcedID.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 3a db 74 4f 66 89 44 24 36 b8 3e 00 00 00 e9 c0 01 00 00 48 83 ec 68 48 c7 44 24 20 00 00 00 00 66 3b e4 74 00 } 		$a_01_1 = {62 69 61 79 75 73 64 6a 61 73 64 75 67 61 79 73 68 67 64 6a 61 6b 73 61 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}