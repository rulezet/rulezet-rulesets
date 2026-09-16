rule Trojan_Win32_Raccrypt_GI_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {77 35 a0 44 c7 44 24 ?? 93 35 23 2d c7 44 24 ?? 99 da f3 4c c7 44 24 ?? c3 f1 76 08 c7 44 24 ?? d9 ba db 67 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}