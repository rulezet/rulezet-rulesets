rule Trojan_Win32_Zusy_GTM_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4c 05 ?? 8d 34 71 33 75 ?? 40 83 f8 } 		$a_03_1 = {8a 44 0d d4 32 04 3a 32 c2 41 83 f9 ?? 88 04 3a ?? ?? 33 c9 42 3b d6 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}