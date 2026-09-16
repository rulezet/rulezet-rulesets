rule VirTool_Win32_Obfuscator_PX_2{
	meta:
		description = "VirTool:Win32/Obfuscator.PX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {51 8d 52 7b 59 8d 40 7b 53 8d 40 85 5b 8d 52 85 51 8d 52 7b 59 8d 40 7b } 		$a_03_1 = {e8 f3 10 00 00 c6 85 90 90 fd ff ff 57 8d ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? c6 85 91 fd ff ff 49 } 		$a_03_2 = {68 00 3e 96 bc ff b5 28 f4 ff ff e8 ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? ff d0 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}