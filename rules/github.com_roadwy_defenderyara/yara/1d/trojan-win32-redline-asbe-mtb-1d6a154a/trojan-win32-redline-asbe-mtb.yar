rule Trojan_Win32_Redline_ASBE_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 80 34 1e ?? 6a 6f 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 04 1e ?? 6a 6f 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 80 04 1e ?? 83 c4 ?? 46 3b f7 0f 82 } 		$a_03_1 = {83 c4 08 8b 55 08 03 55 fc 0f b6 02 83 f0 ?? 8b 4d 08 03 4d fc 88 01 6a 6f 68 } 		$a_01_2 = {44 53 75 79 67 61 63 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}