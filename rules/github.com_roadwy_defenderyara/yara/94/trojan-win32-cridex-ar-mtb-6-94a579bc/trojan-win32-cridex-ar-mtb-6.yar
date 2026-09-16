rule Trojan_Win32_Cridex_AR_MTB_6{
	meta:
		description = "Trojan:Win32/Cridex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c3 2c 8f 04 01 89 1a 0f b7 2d ?? ?? ?? ?? 8b d0 2b d7 0f b7 3d ?? ?? ?? ?? 2b fd 81 ea 12 9d 00 00 a3 ?? ?? ?? ?? 81 ff 67 01 00 00 75 0e } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}