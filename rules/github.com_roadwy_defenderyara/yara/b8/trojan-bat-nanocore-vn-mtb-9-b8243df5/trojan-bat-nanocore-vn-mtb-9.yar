rule Trojan_BAT_NanoCore_VN_MTB_9{
	meta:
		description = "Trojan:BAT/NanoCore.VN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {4f 4a 49 41 55 48 44 4f 55 48 44 55 4f 41 44 47 } 		$a_81_1 = {70 61 73 73 77 6f 72 64 } 		$a_81_2 = {42 6c 6f 63 6b 43 6f 70 79 } 		$a_81_3 = {24 32 32 66 65 36 34 38 66 2d 32 65 36 62 2d 34 62 38 61 2d 62 62 35 62 2d 30 32 30 66 34 65 33 38 32 38 61 34 } 		$a_81_4 = {53 6e 61 6b 65 54 72 6f 6f 70 73 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}