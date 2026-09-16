rule Trojan_Win32_ICLoader_GTM_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 c7 44 24 08 04 3a 5c 00 01 04 24 } 		$a_03_1 = {8d 00 01 8d ?? ?? ?? ?? ?? 00 83 ?? ?? ?? ?? 29 ca 00 01 8d 14 d6 c7 02 ?? ?? ?? ?? c7 42 } 	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}