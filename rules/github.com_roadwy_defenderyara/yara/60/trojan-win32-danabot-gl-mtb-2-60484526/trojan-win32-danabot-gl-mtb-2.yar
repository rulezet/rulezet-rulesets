rule Trojan_Win32_DanaBot_GL_MTB_2{
	meta:
		description = "Trojan:Win32/DanaBot.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 d6 33 ca 81 3d [0-15] c7 05 [0-15] 89 1d [0-15] 89 8d } 		$a_00_1 = {8b 85 d8 f7 ff ff 8b 4d fc 89 78 04 5f 89 30 5e 33 cd 5b e8 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}