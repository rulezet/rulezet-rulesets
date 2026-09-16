rule Trojan_Win32_Raccrypt_GS_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6c 89 1a 60 c7 44 24 ?? b8 38 69 0e c7 44 24 ?? 7d 00 8d 51 c7 44 24 ?? d2 fb 1a 43 c7 44 24 ?? 2c 31 1b 28 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}