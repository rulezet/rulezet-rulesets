rule Trojan_AndroidOS_Dvmap_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Dvmap.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {31 35 2e 74 68 72 65 61 64 73 74 61 72 74 } 		$a_00_1 = {59 32 39 74 4c 6e 46 31 59 57 78 6a 62 57 30 75 64 47 6c 74 5a 58 4e 6c 63 6e 5a 70 59 32 56 7a } 		$a_00_2 = {47 61 6d 65 33 32 25 64 2e 72 65 73 } 		$a_00_3 = {72 6f 6f 74 5f 66 61 69 6c } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}