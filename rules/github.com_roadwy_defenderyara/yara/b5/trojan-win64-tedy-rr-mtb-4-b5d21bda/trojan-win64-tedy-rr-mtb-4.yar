rule Trojan_Win64_Tedy_RR_MTB_4{
	meta:
		description = "Trojan:Win64/Tedy.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 69 73 63 6f 72 64 5f 67 61 6d 65 5f 73 64 6b 2e 64 6c 6c } 		$a_01_1 = {44 69 73 63 6f 72 64 43 72 65 61 74 65 } 		$a_01_2 = {61 70 69 2d 6d 73 2d 77 69 6e 2d 63 72 74 2d 6c 6f 63 61 6c 65 2d 6c 31 2d 31 2d 30 2e 64 6c 6c } 		$a_01_3 = {36 6f 6f 50 62 41 50 54 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}