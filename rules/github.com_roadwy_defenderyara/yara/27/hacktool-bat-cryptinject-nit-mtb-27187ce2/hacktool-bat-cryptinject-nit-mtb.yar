rule HackTool_BAT_CryptInject_NIT_MTB{
	meta:
		description = "HackTool:BAT/CryptInject.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 08 18 5b 02 08 18 6f 68 01 00 0a 1f 10 28 6d 01 00 0a 9c 08 18 58 0c 08 06 32 e4 } 		$a_01_1 = {02 28 08 00 00 06 7e 0e 00 00 04 25 2d 17 26 7e 0a 00 00 04 fe 06 1c 00 00 06 73 41 00 00 0a 25 80 0e 00 00 04 28 07 00 00 2b 28 08 00 00 2b 0a 28 43 00 00 0a 03 6f 44 00 00 0a 06 06 8e 69 28 06 00 00 06 2a } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}