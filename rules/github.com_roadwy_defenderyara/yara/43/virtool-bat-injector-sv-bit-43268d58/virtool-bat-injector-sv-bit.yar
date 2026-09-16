rule VirTool_BAT_Injector_SV_bit{
	meta:
		description = "VirTool:BAT/Injector.SV!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 00 33 00 56 00 68 00 64 00 57 00 4e 00 73 00 64 00 43 00 51 00 3d 00 } 		$a_01_1 = {5c 77 6d 70 6e 65 74 77 6b 5c 77 6d 70 6e 65 74 77 6b } 		$a_01_2 = {5f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 24 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}