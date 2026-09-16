rule HackTool_BAT_Protoon_A_4{
	meta:
		description = "HackTool:BAT/Protoon.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 62 6f 61 72 64 20 4c 6f 67 20 2d 20 50 72 6f 74 6f 6e 20 52 41 54 } 		$a_01_1 = {5c 00 50 00 72 00 6f 00 74 00 6f 00 6e 00 5c 00 4b 00 42 00 4c 00 6f 00 67 00 73 00 } 		$a_01_2 = {7b 00 30 00 7d 00 5c 00 4b 00 42 00 2d 00 7b 00 31 00 7d 00 2e 00 7b 00 32 00 7d 00 2e 00 7b 00 33 00 7d 00 2e 00 6c 00 6f 00 67 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}