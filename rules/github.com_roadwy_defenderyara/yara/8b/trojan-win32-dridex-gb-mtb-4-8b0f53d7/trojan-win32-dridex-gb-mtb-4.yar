rule Trojan_Win32_Dridex_GB_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {6f c6 44 24 ?? 63 c6 44 24 ?? 00 8a 84 24 ?? 00 00 00 88 84 24 ?? 00 00 00 c6 84 24 ?? 00 00 00 58 89 54 24 ?? e8 ?? ?? ?? ?? 8b 54 24 ?? 66 8b 5c 24 ?? 66 89 9c 24 ?? 00 00 00 89 04 24 89 54 24 ?? e8 } 		$a_02_1 = {72 c6 44 24 ?? 6e 8a 74 24 ?? 80 f6 ?? 88 b4 24 ?? 00 00 00 80 f1 ?? 88 54 24 ?? c6 44 24 ?? 6c 66 8b 74 24 1c } 	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}