rule VirTool_BAT_Injector_EK{
	meta:
		description = "VirTool:BAT/Injector.EK,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {d6 20 ff 00 00 00 5f 91 06 09 91 61 9c 09 17 d6 } 		$a_01_1 = {00 41 00 44 49 00 4b 65 79 62 6f 61 72 64 48 6f 6f 6b 00 44 43 49 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}