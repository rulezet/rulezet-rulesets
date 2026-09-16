rule Trojan_Win32_Emotet_AD_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {89 45 f8 81 75 f8 ?? ?? ?? ?? 8a 4d f8 8b 75 fc c7 45 f8 } 		$a_03_1 = {89 45 f8 c1 65 f8 04 81 75 f8 ?? ?? ?? ?? 8a 4d f8 8b 55 fc 0f be 03 89 45 fc } 		$a_01_2 = {01 75 fc d3 e2 01 55 fc } 		$a_01_3 = {29 7d fc 43 80 3b 00 75 a4 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}