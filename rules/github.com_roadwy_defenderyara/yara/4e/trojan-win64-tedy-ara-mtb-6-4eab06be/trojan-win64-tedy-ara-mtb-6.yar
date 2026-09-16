rule Trojan_Win64_Tedy_ARA_MTB_6{
	meta:
		description = "Trojan:Win64/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 53 74 61 72 74 75 70 5c 4e 56 49 44 49 41 47 72 61 70 68 69 63 73 2e 6c 6e 6b } 		$a_01_1 = {5c 53 74 61 72 74 75 70 5c 4d 69 63 72 6f 73 6f 66 74 44 65 66 65 6e 64 65 72 2e 6c 6e 6b } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}