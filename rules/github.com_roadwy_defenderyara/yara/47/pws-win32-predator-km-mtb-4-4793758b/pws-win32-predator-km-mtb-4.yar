rule PWS_Win32_Predator_KM_MTB_4{
	meta:
		description = "PWS:Win32/Predator.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {43 6f 69 6e 73 5c 25 73 5c 77 61 6c 6c 65 74 2e 64 61 74 } 		$a_80_1 = {50 61 73 73 77 6f 72 64 73 4c 69 73 74 2e 74 78 74 } 		$a_80_2 = {43 6f 69 6e 73 5c 4e 61 6d 65 63 6f 69 6e 5c 77 61 6c 6c 65 74 2e 64 61 74 } 		$a_80_3 = {43 6f 69 6e 73 5c 4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 5f 25 64 2e 64 61 74 } 		$a_80_4 = {43 6f 6f 6b 69 65 4c 69 73 74 2e 74 78 74 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}