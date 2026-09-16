rule VirTool_Win32_CryptInject_MTB_3{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_02_1 = {83 ff 00 0f 8d ?? ?? ff ff 90 0a 50 00 29 df 90 0a 50 00 8f 04 38 90 0a 50 00 ff 75 34 90 0a 50 00 31 75 34 90 0a 50 00 8f 45 34 90 0a 50 00 ff 34 3a } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}