rule Trojan_Win32_Emotetcrypt_RM_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e2 07 03 c2 8b c8 c1 f9 03 69 c9 b4 00 00 00 8b c7 2b c1 03 c6 8a c8 32 8d ?? ?? ?? ?? 85 db 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}