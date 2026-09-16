rule HackTool_BAT_Protoon_A_3{
	meta:
		description = "HackTool:BAT/Protoon.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 75 6e 6e 79 54 6f 6f 6c 73 43 6c 69 65 6e 74 } 		$a_01_1 = {48 61 72 64 77 61 72 65 43 6f 6d 6d 61 6e 64 73 } 		$a_01_2 = {48 61 6e 64 6c 65 4d 69 73 63 43 6f 6d 6d 61 6e 64 73 } 		$a_01_3 = {73 00 65 00 74 00 20 00 43 00 44 00 41 00 75 00 64 00 69 00 6f 00 20 00 64 00 6f 00 6f 00 72 00 20 00 6f 00 70 00 65 00 6e 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}