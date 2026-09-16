rule Trojan_Win32_Raccoon_RE_MTB_6{
	meta:
		description = "Trojan:Win32/Raccoon.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 00 61 00 6c 00 6c 00 65 00 74 00 2e 00 64 00 61 00 74 00 } 		$a_01_1 = {6d 00 6f 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 7a 00 } 		$a_01_2 = {73 73 74 6d 6e 66 6f 5f } 		$a_03_3 = {40 8a 0c 85 ?? ?? ?? ?? 8b 45 08 32 0c 03 a1 ?? ?? ?? ?? 88 0c 18 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}