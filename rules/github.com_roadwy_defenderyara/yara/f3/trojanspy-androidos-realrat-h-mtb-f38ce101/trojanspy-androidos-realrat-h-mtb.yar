rule TrojanSpy_AndroidOS_RealRat_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RealRat.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 70 69 78 6f 2f 72 61 74 2f 6d 61 69 6e } 		$a_00_1 = {4c 63 6f 6d 2f 72 65 7a 61 2f 73 68 2f 64 65 76 69 63 65 69 6e 66 6f } 		$a_00_2 = {35 2e 32 35 35 2e 31 31 37 2e 31 31 35 } 		$a_00_3 = {50 4e 55 70 6c 6f 61 64 46 69 6c 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}