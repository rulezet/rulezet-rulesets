rule Trojan_Win32_Amadey_AMY_MTB_4{
	meta:
		description = "Trojan:Win32/Amadey.AMY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 56 57 8b f9 ff 77 04 ff 15 70 b5 69 00 8b f0 56 ff 15 38 b5 69 00 89 45 d8 0f 57 c0 8d 45 ec } 		$a_01_1 = {54 45 4d 50 5c 70 69 78 65 6c 73 65 65 2d 69 6e 73 74 61 6c 6c 65 72 2d 74 6d 70 } 		$a_01_2 = {4d 65 64 69 61 47 65 74 5c 6d 65 64 69 61 67 65 74 2e 65 78 65 } 		$a_01_3 = {50 69 78 65 6c 53 65 65 20 4c 4c 43 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}