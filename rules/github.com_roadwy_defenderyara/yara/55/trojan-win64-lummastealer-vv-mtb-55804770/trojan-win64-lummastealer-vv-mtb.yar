rule Trojan_Win64_LummaStealer_VV_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.VV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {74 65 73 74 5f 6c 69 62 2f 6d 61 69 6e 2e 67 6f } 		$a_01_1 = {6d 61 69 6e 2e 71 48 62 4c 4b 63 56 46 50 59 } 		$a_01_2 = {6d 61 69 6e 2e 42 6e 4d 57 6e 70 55 79 63 4f } 		$a_01_3 = {6d 61 69 6e 2e 48 46 64 72 51 63 4c 52 54 68 } 		$a_01_4 = {6d 61 69 6e 2e 48 77 4e 63 54 62 6c 5a 78 4a } 		$a_01_5 = {6d 61 69 6e 2e 6b 68 67 7a 42 77 4f 63 64 53 } 		$a_01_6 = {6d 61 69 6e 2e 52 44 46 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=8
 
}