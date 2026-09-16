rule Trojan_Win32_Guloader_AL_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {f8 81 dc fc 01 00 00 40 55 89 e5 e8 00 00 00 00 58 83 e8 10 89 45 44 e8 ?? ?? 00 00 e9 ?? 00 00 } 		$a_03_1 = {31 10 f8 83 c0 04 39 d8 0f 85 ?? ?? ff ff } 		$a_03_2 = {64 8b 1d c0 00 00 00 81 fe ?? ?? ?? ?? 83 fb 00 74 26 eb 25 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}