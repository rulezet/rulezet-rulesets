rule Trojan_Win32_Smokeloader_GMZ_MTB_2{
	meta:
		description = "Trojan:Win32/Smokeloader.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 65 76 20 6e 65 66 75 6b 75 6c 75 6c 65 70 65 64 65 79 } 		$a_01_1 = {74 69 70 69 76 61 67 6f 63 69 6d 6f 77 69 79 61 } 		$a_80_2 = {78 61 66 65 63 65 6c 6f 63 69 78 75 70 61 70 65 64 61 68 65 73 6f 66 75 6e 65 7a 6f 64 69 63 65 78 65 67 65 6e 6f 67 65 78 65 70 75 6d 61 77 6f 6a 75 79 61 67 6f 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}