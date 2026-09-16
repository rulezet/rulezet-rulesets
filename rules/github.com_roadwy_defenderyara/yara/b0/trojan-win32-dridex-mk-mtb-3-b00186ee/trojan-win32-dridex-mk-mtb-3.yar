rule Trojan_Win32_Dridex_MK_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 eb 01 03 f3 8d 7c 37 ec 8d 77 e7 8b c6 6b c0 ?? 2b c5 01 05 ?? ?? ?? ?? 85 db 75 e3 } 		$a_03_1 = {0f b7 cb 8d 5c 02 ?? 8b c2 6b c0 ?? 8d 6c 29 c9 8b 0e 81 c1 ?? ?? ?? ?? 89 0e 2b c5 83 c6 ?? 83 6c 24 10 ?? 89 2d ?? ?? ?? ?? 8d 44 38 da 75 99 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}