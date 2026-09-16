rule Trojan_Win32_ShellLoader_SX_MTB{
	meta:
		description = "Trojan:Win32/ShellLoader.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 1c b8 03 de 8b f2 8a 0b 6b f6 7f 0f be c1 03 f0 43 84 c9 75 f1 8b 5d f4 89 75 f0 8b 75 f8 3b 5d f0 74 08 47 3b 7d ec 72 d3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}