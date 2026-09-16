rule Trojan_Win32_Raccrypt_GL_MTB{
	meta:
		description = "Trojan:Win32/Raccrypt.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? c3 81 05 ?? ?? ?? ?? d6 38 00 00 c3 81 05 ?? ?? ?? ?? 00 00 00 00 c3 ff 25 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}