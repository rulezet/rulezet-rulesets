rule Trojan_Win32_Guloader_AK_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 0f 85 d2 e8 ?? ?? 00 00 85 c0 39 c1 75 ?? eb } 		$a_01_1 = {eb 02 00 00 ff e0 } 		$a_01_2 = {0f 6e da 66 85 db 31 f1 85 ff c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}