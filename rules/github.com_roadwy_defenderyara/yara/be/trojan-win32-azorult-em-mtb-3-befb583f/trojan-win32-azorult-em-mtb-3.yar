rule Trojan_Win32_Azorult_EM_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c0 f3 0f 58 c8 0f 57 c0 f3 0f 2a c0 f3 0f 58 c8 0f 57 c0 } 		$a_01_1 = {8b f9 2b f8 89 7c 24 40 8b 7c 24 58 8b 44 24 5c 8a 54 24 67 88 10 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}