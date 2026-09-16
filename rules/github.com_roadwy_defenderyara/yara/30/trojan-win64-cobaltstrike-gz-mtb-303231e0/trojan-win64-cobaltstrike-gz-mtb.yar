rule Trojan_Win64_CobaltStrike_GZ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {62 72 69 64 69 70 69 76 6d 73 6e 73 75 70 75 73 } 		$a_01_1 = {47 4f 4d 41 58 50 52 4f 43 53 } 		$a_01_2 = {4f 54 54 4f 74 74 63 66 77 4f 46 46 77 4f 46 32 50 4b } 		$a_01_3 = {20 47 6f 20 62 75 69 6c 64 69 6e 66 3a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}