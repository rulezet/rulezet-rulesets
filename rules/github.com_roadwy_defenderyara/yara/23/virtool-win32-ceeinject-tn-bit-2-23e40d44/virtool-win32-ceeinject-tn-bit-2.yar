rule VirTool_Win32_CeeInject_TN_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TN!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 } 		$a_03_1 = {8d 48 fb 30 4c 05 ?? 40 83 f8 0c } 		$a_03_2 = {8d 34 08 8d 50 fb 40 30 16 83 f8 ?? 72 f2 } 		$a_00_3 = {0f be d3 8d 76 01 c1 c8 0d 80 fb 61 8a 1e 8d 4a e0 0f 4c ca 03 c1 84 db 75 e6 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}