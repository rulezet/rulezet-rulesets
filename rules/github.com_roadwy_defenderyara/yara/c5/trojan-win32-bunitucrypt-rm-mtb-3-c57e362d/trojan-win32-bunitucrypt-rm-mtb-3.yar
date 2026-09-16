rule Trojan_Win32_BunituCrypt_RM_MTB_3{
	meta:
		description = "Trojan:Win32/BunituCrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 18 33 c0 89 45 ?? 8b 45 ?? 83 c0 04 01 45 ?? 8b 45 ?? 83 c0 04 } 		$a_00_1 = {2d 00 10 00 00 83 c0 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}