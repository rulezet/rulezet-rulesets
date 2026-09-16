rule Trojan_Win64_Tedy_ARA_MTB_3{
	meta:
		description = "Trojan:Win64/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 75 72 6c 20 2d 46 20 22 69 6d 61 67 65 3d 40 } 		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 2e 77 69 6e 53 65 73 73 69 6f 6e } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}