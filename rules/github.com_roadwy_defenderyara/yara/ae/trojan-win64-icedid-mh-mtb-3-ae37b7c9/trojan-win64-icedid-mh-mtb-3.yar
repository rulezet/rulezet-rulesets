rule Trojan_Win64_IcedID_MH_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_1 = {51 55 71 73 32 73 7a 6b 48 68 6e } 		$a_01_2 = {4b 4b 52 41 55 2e 64 6c 6c } 		$a_01_3 = {72 64 52 54 61 44 49 43 } 		$a_01_4 = {73 67 4e 6b 41 59 41 76 52 4c 39 } 		$a_01_5 = {78 57 57 35 51 4d } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}