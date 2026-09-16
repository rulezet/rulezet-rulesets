rule Trojan_Win32_Raccrypt_GT_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 04 0a 81 bc 24 ?? ?? ?? ?? 91 05 00 00 90 18 41 3b 8c 24 ?? ?? ?? ?? 89 4c 24 ?? 0f 8c } 		$a_02_1 = {91 05 00 00 75 56 90 0a 14 00 8b 4c 24 ?? 30 04 ?? 81 bc 24 ?? ?? 00 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}