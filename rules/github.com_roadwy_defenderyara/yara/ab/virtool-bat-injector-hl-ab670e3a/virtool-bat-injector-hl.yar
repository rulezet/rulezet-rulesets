rule VirTool_BAT_Injector_HL{
	meta:
		description = "VirTool:BAT/Injector.HL,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 00 0e 00 00 8d 05 00 00 01 13 06 11 06 16 1f ?? 9c 11 06 17 1f 16 9c 11 06 18 20 d5 00 00 00 9c 11 06 19 1f 54 9c 11 06 1a 1f 6b 9c 11 06 1b 1f 6a 9c 11 06 1c 1f 4a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}