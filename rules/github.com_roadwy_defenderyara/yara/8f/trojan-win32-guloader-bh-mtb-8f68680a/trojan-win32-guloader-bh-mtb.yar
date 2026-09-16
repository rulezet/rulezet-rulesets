rule Trojan_Win32_Guloader_BH_MTB{
	meta:
		description = "Trojan:Win32/Guloader.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 e9 04 81 34 0b ?? ?? ?? ?? [0-06] 83 f9 00 75 ?? 53 eb } 		$a_01_1 = {50 89 e0 83 c4 06 ff 28 e8 90 01 01 ff ff ff c3 } 		$a_03_2 = {85 db 64 8b 1d c0 00 00 00 83 fb 00 74 ?? eb } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}