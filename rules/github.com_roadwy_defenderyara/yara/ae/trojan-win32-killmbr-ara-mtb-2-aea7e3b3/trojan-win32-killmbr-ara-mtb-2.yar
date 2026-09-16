rule Trojan_Win32_KillMBR_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 6a 00 6a 00 6a 03 6a 00 6a 03 68 00 00 00 10 68 00 21 40 00 ff 15 ?? ?? ?? ?? 6a 00 8b f0 8d 45 f8 50 68 00 02 00 00 68 28 21 40 00 56 ff 15 ?? ?? ?? ?? 56 ff 15 } 		$a_80_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } 	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}