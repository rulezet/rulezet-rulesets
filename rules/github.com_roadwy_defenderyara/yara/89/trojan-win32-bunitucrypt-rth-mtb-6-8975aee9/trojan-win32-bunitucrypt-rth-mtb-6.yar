rule Trojan_Win32_BunituCrypt_RTH_MTB_6{
	meta:
		description = "Trojan:Win32/BunituCrypt.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ?? 04 83 45 } 		$a_03_1 = {2b d8 01 5d ?? 8b 45 ?? 01 45 ?? eb ?? c7 45 ?? 8a a5 08 00 8b 45 ?? 3b 45 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}