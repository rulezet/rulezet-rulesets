rule Trojan_Win32_Zusy_GPAC_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.GPAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 41 74 74 65 6e 64 61 6e 63 65 52 53 } 		$a_01_1 = {4f 44 42 43 3b 44 53 4e 3d 4d 49 53 44 42 } 		$a_01_2 = {5b 50 45 52 53 4f 4e 5d 00 00 00 00 5b 49 44 5d } 		$a_81_3 = {43 45 72 72 61 6e 64 52 53 } 		$a_81_4 = {43 4c 65 61 76 65 52 53 } 	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}