rule TrojanDownloader_Win64_IcedID_ADC_MTB_2{
	meta:
		description = "TrojanDownloader:Win64/IcedID.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {41 6c 4f 4c 59 4e 65 50 63 } 		$a_80_1 = {41 78 57 62 63 74 6d 76 41 78 6d 48 77 4a 6d 62 55 6c } 		$a_80_2 = {42 61 66 41 46 47 6a 41 6c 4b 62 63 6c 4b 48 41 42 43 } 		$a_80_3 = {44 51 4e 4f 72 6b 70 75 4c 6b 74 57 } 		$a_80_4 = {57 72 69 74 65 43 6f 6e 73 6f 6c 65 57 } 		$a_80_5 = {49 73 56 61 6c 69 64 4c 6f 63 61 6c 65 } 		$a_80_6 = {45 6e 75 6d 53 79 73 74 65 6d 4c 6f 63 61 6c 65 73 57 } 	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}