rule VirTool_Win32_CryptInject_MTB_2{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_02_1 = {83 c1 04 0f 8d ?? ?? ff ff 90 0a ff 00 ff 34 0f [0-30] 5b [0-30] 31 f3 [0-30] 89 1c 0a [0-40] 83 e9 08 [0-30] 83 c1 04 0f 8d ?? ?? ff ff } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}