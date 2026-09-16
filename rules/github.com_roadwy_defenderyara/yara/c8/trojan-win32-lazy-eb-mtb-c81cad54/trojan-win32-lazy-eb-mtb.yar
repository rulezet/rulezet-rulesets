rule Trojan_Win32_Lazy_EB_MTB{
	meta:
		description = "Trojan:Win32/Lazy.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 77 78 75 6e 69 7a } 		$a_01_1 = {77 6a 67 75 63 74 68 70 7a } 		$a_01_2 = {63 6d 65 79 6c 64 70 77 75 6a 68 } 		$a_01_3 = {63 62 66 6b 69 65 6c 76 71 74 } 		$a_01_4 = {79 6b 67 70 68 6c 6f 72 6d 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}