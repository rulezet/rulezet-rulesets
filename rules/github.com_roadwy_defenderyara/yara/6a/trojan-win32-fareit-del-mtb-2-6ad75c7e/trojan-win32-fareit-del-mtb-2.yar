rule Trojan_Win32_Fareit_DEL_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.DEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_81_0 = {73 32 59 58 45 4b 46 41 30 4b 6b } 		$a_81_1 = {35 56 53 4b 30 63 34 50 50 68 5a 41 59 61 54 74 4e } 		$a_02_2 = {89 1e a1 60 bc 47 00 03 06 8a 00 34 ?? 8b 15 60 bc 47 00 03 16 88 02 ?? ?? 43 81 fb ?? ?? ?? ?? 75 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_02_2  & 1)*2) >=2
 
}