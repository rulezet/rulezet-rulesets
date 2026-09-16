rule Trojan_Win32_Lazy_ALZ_MTB_3{
	meta:
		description = "Trojan:Win32/Lazy.ALZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 68 58 1d 62 67 6a 00 ff 15 ?? ?? ?? ?? 68 98 1d 62 67 89 85 74 17 ff ff ff 15 ?? ?? ?? ?? 68 a4 1d 62 67 50 ff 15 } 		$a_03_1 = {50 6a 00 8d 85 44 19 ff ff 50 ff 15 ?? ?? ?? ?? 8b b5 74 17 ff ff 8d 85 c0 2d ff ff 50 56 ff 15 ?? ?? ?? ?? 8b 3d fc c1 61 67 8d 85 c0 2d ff ff 50 56 ff d7 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}