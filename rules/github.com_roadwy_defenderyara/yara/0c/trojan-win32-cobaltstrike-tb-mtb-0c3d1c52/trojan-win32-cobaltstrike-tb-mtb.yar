rule Trojan_Win32_CobaltStrike_TB_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.TB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 63 c0 46 8a 04 02 41 b9 ?? ?? ?? ?? 31 d2 41 f7 f1 8b 44 24 ?? 41 89 d1 48 8b 54 24 ?? 4d 63 c9 46 32 04 0a 48 63 d0 44 88 04 11 83 c0 01 31 c9 89 ca 48 b9 ?? ?? ?? ?? ?? ?? ?? ?? 48 29 ca 31 c9 49 b8 ?? ?? ?? ?? ?? ?? ?? ?? 4c 29 c1 83 f8 ?? 48 0f 44 ca } 		$a_01_1 = {2f 00 6d 00 6f 00 64 00 65 00 6c 00 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 70 00 68 00 70 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}