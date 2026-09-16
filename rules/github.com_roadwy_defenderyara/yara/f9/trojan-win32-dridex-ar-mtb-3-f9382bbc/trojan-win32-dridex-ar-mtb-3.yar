rule Trojan_Win32_Dridex_AR_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 08 8b 4d fc 03 0d ?? ?? ?? ?? 8b 55 f4 03 15 ?? ?? ?? ?? 8a 02 88 01 33 c9 0f 84 ?? ?? ?? ?? 6a 04 6a 04 } 		$a_00_1 = {8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d 87 10 00 00 8b 4d 08 89 01 5e 8b e5 5d c3 } 	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}