rule Trojan_Win32_Raccoon_RJ_MTB_5{
	meta:
		description = "Trojan:Win32/Raccoon.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 ?? 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ?? 0f b6 45 ?? 8b 4d ?? 0f b6 91 ?? ?? ?? ?? 03 d0 8b 45 ?? 88 [0-20] 2b c8 88 4d [0-15] 2b ca 8b 55 ?? 88 8a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}