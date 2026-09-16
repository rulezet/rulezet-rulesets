rule Trojan_Win64_IcedID_DC_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_1 = {69 4c 71 56 6b 2e 64 6c 6c } 		$a_01_2 = {41 78 30 4b 52 46 33 47 30 68 } 		$a_01_3 = {43 67 4e 4d 5a 68 59 41 45 6c 64 } 		$a_01_4 = {4a 4f 47 30 64 78 36 74 77 55 } 		$a_01_5 = {4b 54 4d 42 74 67 6c 32 62 45 41 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}