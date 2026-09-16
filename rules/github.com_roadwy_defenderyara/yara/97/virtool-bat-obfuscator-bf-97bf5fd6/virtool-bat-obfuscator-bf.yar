rule VirTool_BAT_Obfuscator_BF{
	meta:
		description = "VirTool:BAT/Obfuscator.BF,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {02 06 02 06 91 03 07 91 61 d2 9c 07 17 58 0b 07 03 8e 69 32 } 		$a_03_1 = {0c 1a 07 6f ?? ?? ?? ?? 5a 07 6f ?? ?? ?? ?? 5a 8d } 		$a_01_2 = {50 69 78 65 6c 46 6f 72 6d 61 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}