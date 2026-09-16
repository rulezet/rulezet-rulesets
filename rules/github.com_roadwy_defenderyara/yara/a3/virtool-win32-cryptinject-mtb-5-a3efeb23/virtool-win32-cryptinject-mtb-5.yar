rule VirTool_Win32_CryptInject_MTB_5{
	meta:
		description = "VirTool:Win32/CryptInject!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_02_1 = {66 0f 6e c6 [0-10] 66 0f 6e c9 [0-10] c5 f0 57 c8 [0-10] 66 0f 7e c9 [0-10] 39 c1 90 13 0f 77 [0-10] 46 [0-10] ff 37 [0-10] 59 } 		$a_02_2 = {66 0f 6e c6 [0-10] 66 0f 6e c9 [0-10] 66 0f ef c8 [0-10] 66 0f 7e c9 [0-10] 39 c1 90 13 0f 77 [0-10] 46 [0-10] ff 37 [0-10] 59 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}