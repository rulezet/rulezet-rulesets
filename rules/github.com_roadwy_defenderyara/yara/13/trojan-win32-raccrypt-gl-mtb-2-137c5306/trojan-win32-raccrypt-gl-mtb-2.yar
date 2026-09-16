rule Trojan_Win32_Raccrypt_GL_MTB_2{
	meta:
		description = "Trojan:Win32/Raccrypt.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {32 2e 64 6c c7 05 ?? ?? ?? ?? 6b 65 72 6e 66 c7 05 ?? ?? ?? ?? 65 6c c6 05 ?? ?? ?? ?? 33 66 c7 05 ?? ?? ?? ?? 6c 00 ff 15 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}