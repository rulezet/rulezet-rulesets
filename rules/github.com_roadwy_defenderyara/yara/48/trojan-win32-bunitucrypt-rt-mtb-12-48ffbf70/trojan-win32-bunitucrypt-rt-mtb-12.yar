rule Trojan_Win32_BunituCrypt_RT_MTB_12{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 [0-05] 0e 00 00 00 } 		$a_03_1 = {31 02 83 45 ?? 04 6a 00 e8 ?? ?? ?? ?? 8b d8 83 c3 04 6a 00 e8 ?? ?? ?? ?? 2b d8 01 ?? ?? 8b ?? ?? 3b ?? ?? 0f [0-14] 2d 00 10 00 00 83 c0 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}