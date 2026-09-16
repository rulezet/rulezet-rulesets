rule VirTool_BAT_NetInject_B{
	meta:
		description = "VirTool:BAT/NetInject.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 85 02 a0 60 e8 ?? ?? ff ff 68 84 2a ab 54 50 e8 ?? ?? ff ff ff d0 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}