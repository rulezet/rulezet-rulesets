rule VirTool_Win32_VBInject_AGV_bit_2{
	meta:
		description = "VirTool:Win32/VBInject.AGV!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {be 4b 00 53 00 [0-10] 39 33 [0-10] 81 7b 04 56 00 42 00 } 		$a_03_1 = {68 55 8b ec 83 [0-10] 5b [0-10] 03 04 24 [0-10] 39 18 [0-10] 81 78 04 ec 0c 56 8d } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}