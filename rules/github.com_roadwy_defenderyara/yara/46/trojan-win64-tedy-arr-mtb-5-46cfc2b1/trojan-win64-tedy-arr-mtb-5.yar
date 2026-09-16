rule Trojan_Win64_Tedy_ARR_MTB_5{
	meta:
		description = "Trojan:Win64/Tedy.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 2b c8 0f b6 44 0c 30 43 32 04 10 41 88 00 4c 3b ce } 		$a_81_1 = {62 79 70 61 73 73 5c 62 79 70 61 73 73 2d 61 67 65 6e 74 5f 32 5c 77 6f 72 6b 73 70 61 63 65 5c 73 73 76 61 67 65 6e 74 5f 6d 75 6c 74 69 5f 78 6f 72 5f } 	condition:
		((#a_01_0  & 1)*16+(#a_81_1  & 1)*4) >=20
 
}