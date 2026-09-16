rule VirTool_BAT_Injector_GM{
	meta:
		description = "VirTool:BAT/Injector.GM,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 23 02 06 02 06 91 05 06 04 5d 91 06 1b 58 05 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 06 17 58 0a 06 02 8e 69 32 d7 02 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}