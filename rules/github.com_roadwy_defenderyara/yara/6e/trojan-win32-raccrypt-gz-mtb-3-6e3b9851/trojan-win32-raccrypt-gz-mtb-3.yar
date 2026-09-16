rule Trojan_Win32_Raccrypt_GZ_MTB_3{
	meta:
		description = "Trojan:Win32/Raccrypt.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {06 f1 1a 2b c7 44 24 ?? f9 0b 2b 23 c7 44 24 ?? 54 d6 ab 00 c7 44 24 ?? d1 f0 0d 7b c7 44 24 ?? 68 17 ab 44 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}