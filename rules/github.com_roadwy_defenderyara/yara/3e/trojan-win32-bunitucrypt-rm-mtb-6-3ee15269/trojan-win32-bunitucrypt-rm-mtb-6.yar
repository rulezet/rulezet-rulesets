rule Trojan_Win32_BunituCrypt_RM_MTB_6{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 ?? 89 18 8b 45 ?? 03 45 ?? 03 45 ?? 8b 55 ?? 31 02 8d 85 ?? ?? ?? ?? 33 c9 ba 3c 00 00 00 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}