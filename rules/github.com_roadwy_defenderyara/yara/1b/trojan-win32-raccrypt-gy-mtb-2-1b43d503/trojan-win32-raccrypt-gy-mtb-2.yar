rule Trojan_Win32_Raccrypt_GY_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8f fb 24 5e c7 85 ?? ?? ?? ?? 76 96 cc 13 c7 85 ?? ?? ?? ?? 68 e3 5c 14 c7 85 ?? ?? ?? ?? aa e4 a4 53 c7 85 ?? ?? ?? ?? cc 54 04 18 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}