rule VirTool_BAT_NetInject_B_2{
	meta:
		description = "VirTool:BAT/NetInject.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 67 4c 6f 61 64 65 72 } 		$a_01_1 = {6c 6f 61 64 65 72 5f 61 72 72 61 79 } 		$a_01_2 = {47 65 74 44 65 6c 65 67 61 74 65 46 6f 72 46 75 6e 63 74 69 6f 6e 50 6f 69 6e 74 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}