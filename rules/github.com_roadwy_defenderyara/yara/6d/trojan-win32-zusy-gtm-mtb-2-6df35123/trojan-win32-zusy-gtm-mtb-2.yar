rule Trojan_Win32_Zusy_GTM_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be 14 10 33 ca 8b 85 ?? ?? ?? ?? 03 45 f8 88 08 } 		$a_01_1 = {03 45 f8 0f be 08 8b 55 f8 81 e2 07 00 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}