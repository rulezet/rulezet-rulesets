rule HackTool_BAT_Protoon_A_2{
	meta:
		description = "HackTool:BAT/Protoon.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 54 6f 6f 6c 73 43 6c 69 65 6e 74 } 		$a_01_1 = {48 61 6e 64 6c 65 43 6f 6e 73 6f 6c 65 43 6f 6d 6d 61 6e 64 73 } 		$a_01_2 = {48 61 6e 64 6c 65 54 61 73 6b 4d 61 6e 61 67 65 72 43 6f 6d 6d 61 6e 64 73 } 		$a_01_3 = {48 61 6e 64 6c 65 52 65 67 69 73 74 72 79 43 6f 6d 6d 61 6e 64 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}