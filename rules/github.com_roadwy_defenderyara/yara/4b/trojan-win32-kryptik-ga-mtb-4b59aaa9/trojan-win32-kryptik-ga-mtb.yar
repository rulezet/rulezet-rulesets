rule Trojan_Win32_Kryptik_GA_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {88 44 24 28 8b 13 8a 44 24 28 8b f1 33 ed 03 f2 8a 16 3a d0 75 1f 8b c7 8b fe 2b 7c 24 2c 84 d2 74 0f 80 38 00 74 } 		$a_02_1 = {8b 75 d8 81 fe 00 00 00 01 77 9b c7 05 ?? ?? ?? ?? 50 72 6f 63 c7 05 ?? ?? ?? ?? 65 73 73 33 c7 05 ?? ?? ?? ?? 32 46 69 72 66 c7 05 ?? ?? ?? ?? 73 74 68 ?? ?? ?? ?? 56 e8 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}