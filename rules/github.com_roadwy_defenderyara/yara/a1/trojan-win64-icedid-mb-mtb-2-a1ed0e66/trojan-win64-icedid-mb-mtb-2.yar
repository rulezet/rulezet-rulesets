rule Trojan_Win64_IcedID_MB_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 51 5a 44 7a 76 50 45 54 6e } 		$a_01_1 = {44 6c 6c 4d 61 69 6e } 		$a_01_2 = {47 63 67 71 43 47 46 65 49 } 		$a_01_3 = {4c 71 76 46 6e 4e 4b 70 4e } 		$a_01_4 = {75 43 75 62 64 4c 6a 78 } 		$a_01_5 = {69 4a 62 61 53 48 65 46 31 34 67 78 4a 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}