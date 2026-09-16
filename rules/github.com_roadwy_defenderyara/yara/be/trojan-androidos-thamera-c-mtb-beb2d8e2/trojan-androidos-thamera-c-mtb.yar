rule Trojan_AndroidOS_Thamera_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Thamera.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 61 6e 6b 6c 32 6b 2e 70 68 70 3f 6b 65 79 3d 31 69 63 79 68 64 38 62 63 37 62 66 71 70 68 6a 65 6d 61 61 26 75 73 65 72 5f 69 64 3d } 		$a_00_1 = {69 73 53 6d 73 43 61 70 61 62 6c 65 } 		$a_00_2 = {66 69 6e 69 73 68 41 6e 64 52 65 6d 6f 76 65 54 61 73 6b } 		$a_00_3 = {4c 63 6f 6d 2f 73 69 6d 70 6c 65 6d 6f 62 69 6c 65 74 6f 6f 6c 73 2f 6c 61 75 6e 63 68 65 72 2f 61 63 74 69 76 69 74 69 65 73 2f 48 69 64 64 65 6e 49 63 6f 6e 73 41 63 74 69 76 69 74 79 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}