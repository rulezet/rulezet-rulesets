rule Trojan_Win64_IcedID_DG_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {71 61 65 6f 4d 2e 64 6c 6c } 		$a_01_1 = {4c 53 45 32 66 37 58 38 59 44 51 } 		$a_01_2 = {55 61 43 59 35 6c 4b 77 6a 49 76 } 		$a_01_3 = {6a 68 62 66 67 79 75 6a 67 68 66 67 64 } 		$a_01_4 = {67 41 41 44 59 75 38 5a 47 } 		$a_01_5 = {58 4b 34 54 4e 38 43 36 4a } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}