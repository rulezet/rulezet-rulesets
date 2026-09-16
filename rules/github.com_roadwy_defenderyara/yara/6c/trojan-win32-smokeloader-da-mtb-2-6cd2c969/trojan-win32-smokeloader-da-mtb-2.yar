rule Trojan_Win32_SmokeLoader_DA_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {0f b6 48 02 eb } 		$a_01_1 = {83 c1 01 eb } 		$a_01_2 = {51 91 59 eb } 		$a_01_3 = {b9 ad 2e 00 00 eb } 		$a_01_4 = {f7 e1 eb 05 } 		$a_01_5 = {01 d8 74 07 } 		$a_01_6 = {89 44 24 fc 83 ec 04 c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}