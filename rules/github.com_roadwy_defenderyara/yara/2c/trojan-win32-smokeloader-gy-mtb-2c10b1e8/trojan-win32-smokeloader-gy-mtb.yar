rule Trojan_Win32_Smokeloader_GY_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4d 6f 6e 69 74 6f 72 49 6e 66 6f } 		$a_01_1 = {47 65 74 54 69 6d 65 5a 6f 6e 65 49 6e 66 6f 72 6d 61 74 69 6f 6e } 		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 		$a_80_3 = {68 75 7a 65 66 75 68 61 74 6f 63 61 6c 75 } 		$a_01_4 = {63 6f 79 75 72 65 7a 61 6a 61 74 65 76 69 70 75 6c 69 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}