rule TrojanDownloader_AndroidOS_SAgnt_B_MTB{
	meta:
		description = "TrojanDownloader:AndroidOS/SAgnt.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6c 5f 61 70 70 75 70 64 61 74 65 } 		$a_00_1 = {2f 41 70 70 55 70 64 61 74 65 45 78 61 6d 70 6c 65 2e 74 78 74 } 		$a_00_2 = {5f 75 70 64 61 74 65 5f 75 70 64 61 74 65 63 6f 6d 70 6c 65 74 65 } 		$a_00_3 = {69 6e 73 74 61 6c 6c 5f 6e 6f 6e 5f 6d 61 72 6b 65 74 5f 61 70 70 73 } 		$a_00_4 = {5f 73 6e 65 77 76 65 72 61 70 6b } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}