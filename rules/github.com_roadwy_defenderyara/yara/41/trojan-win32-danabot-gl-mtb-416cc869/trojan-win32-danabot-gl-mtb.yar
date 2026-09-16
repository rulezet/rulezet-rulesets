rule Trojan_Win32_DanaBot_GL_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f 57 c0 33 c8 66 0f 13 05 [0-30] 81 3d [0-35] 89 4c 24 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}