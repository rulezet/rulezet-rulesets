rule TrojanSpy_BAT_Golroted_B_2{
	meta:
		description = "TrojanSpy:BAT/Golroted.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 6f 6c 64 65 72 4e 5c 6e 61 6d 65 2e 65 78 65 } 		$a_01_1 = {46 6f 6c 64 65 72 4e 5c 6d 61 74 61 32 2e 62 61 74 } 		$a_01_2 = {46 6f 6c 64 65 72 4e 5c 73 76 68 6f 73 74 2e 62 61 74 } 		$a_01_3 = {46 6f 6c 64 65 72 4e 5c 6e 61 6d 65 2e 65 78 65 2e 62 61 74 } 		$a_01_4 = {46 6f 6c 64 65 72 4e 5c 6d 65 6c 74 2e 62 61 74 } 		$a_01_5 = {73 76 68 6f 73 74 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}