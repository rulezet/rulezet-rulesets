rule VirTool_BAT_Inject{
	meta:
		description = "VirTool:BAT/Inject,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 35 3a 6f 42 3e 3f 55 64 3d 49 3b 2a 3e 2c 3f 57 2f 2d 39 36 68 64 60 00 41 74 74 72 69 62 75 74 65 } 		$a_01_1 = {62 61 62 69 67 67 62 6f 79 2e 64 64 6e 73 2e 6e 65 74 } 		$a_01_2 = {6d 6f 64 65 6d 20 6b 69 6c 6c 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}