rule Trojan_Win64_IcedId_FA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedId.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 77 51 69 52 4d 68 63 53 50 4e } 		$a_01_1 = {6d 32 6b 56 4b 59 46 42 4f 61 76 39 35 61 50 6c } 		$a_01_2 = {6d 64 45 51 69 32 70 33 } 		$a_01_3 = {6d 66 6c 64 4b 37 35 36 73 35 6c 39 4a 74 } 		$a_01_4 = {6e 75 79 68 61 66 6a 73 68 79 67 66 61 73 66 6a 61 73 79 6a 61 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}