rule Trojan_Win32_Dridex_AG_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {66 83 c1 63 89 b4 3b a4 e8 ff ff 83 c7 04 8b 1d ?? ?? ?? ?? 66 03 cb 0f b7 d1 89 54 24 10 81 ff 74 18 00 00 73 1e } 		$a_00_1 = {0f b6 c8 8b 44 24 10 0f b7 d5 2b ca 0f b7 c0 83 c1 63 2b c2 03 ce 83 c0 63 03 c1 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}