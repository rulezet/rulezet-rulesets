rule Trojan_Win32_BunituCrypt_RT_MTB_13{
	meta:
		description = "Trojan:Win32/BunituCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 c7 ?? ?? e3 14 00 00 c7 ?? ?? 9f 0a 00 00 } 		$a_03_1 = {33 c0 89 45 ?? 8b 45 ?? 8b 55 ?? 01 10 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}