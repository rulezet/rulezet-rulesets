rule Trojan_Win32_BunituCrypt_RF_MTB_10{
	meta:
		description = "Trojan:Win32/BunituCrypt.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 68 74 2d 4b 00 e8 ?? ?? ?? ?? 68 74 2d 4b 00 e8 ?? ?? ?? ?? 68 74 2d 4b 00 e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}