rule Trojan_Win32_BunituCrypt_RM_MTB_19{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 45 ?? 8b 55 ?? 31 02 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}