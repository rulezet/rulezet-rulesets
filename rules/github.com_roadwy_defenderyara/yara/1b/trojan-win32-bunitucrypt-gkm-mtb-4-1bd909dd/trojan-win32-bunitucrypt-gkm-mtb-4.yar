rule Trojan_Win32_BunituCrypt_GKM_MTB_4{
	meta:
		description = "Trojan:Win32/BunituCrypt.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 d8 68 3b 11 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 ?? 31 18 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 0f 82 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}