rule Trojan_Win32_BunituCrypt_RTH_MTB_5{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a a5 08 00 8b 45 ?? 3b 45 ?? 73 ?? e8 } 		$a_03_1 = {89 18 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}