rule Trojan_Win32_Raccrypt_GM_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 3b 2d 0b 00 01 45 74 8b 45 74 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 0f 82 } 		$a_02_1 = {33 44 24 04 c2 ?? 00 81 00 40 36 ef c6 c3 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}