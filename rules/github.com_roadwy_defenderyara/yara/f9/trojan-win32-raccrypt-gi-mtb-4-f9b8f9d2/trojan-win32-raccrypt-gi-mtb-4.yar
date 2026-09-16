rule Trojan_Win32_Raccrypt_GI_MTB_4{
	meta:
		description = "Trojan:Win32/Raccrypt.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 b9 72 00 00 00 ba 6c 00 00 00 6a 00 c7 05 ?? ?? ?? ?? 64 00 6c 00 c7 05 ?? ?? ?? ?? 6c 00 00 00 66 89 0d ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? ff 15 90 0a 6b 00 ba 65 00 00 00 [0-04] b8 6b 00 00 00 [0-14] ba 2e 00 00 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}