rule Trojan_Win32_BunituCrypt_RM_MTB_16{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 10 83 45 ?? 04 83 45 ?? 04 8b 45 ?? 3b 45 ?? 72 ?? 8b 45 ?? 03 45 ?? 2d 00 10 00 00 [0-05] 83 45 [0-05] 04 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}