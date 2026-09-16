rule Trojan_Win64_IcedID_MN_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_1 = {67 69 4b 43 52 4f 2e 64 6c 6c } 		$a_01_2 = {41 69 4e 42 78 42 50 44 57 44 } 		$a_01_3 = {41 65 46 6a 69 78 68 6c } 		$a_01_4 = {57 57 73 52 45 4a 7a 6a } 		$a_01_5 = {43 56 4f 4c 58 55 44 6e } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}