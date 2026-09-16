rule VirTool_Win32_Obfuscator_AKI_2{
	meta:
		description = "VirTool:Win32/Obfuscator.AKI,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {80 3a 50 74 } 		$a_01_1 = {80 38 4c 74 } 		$a_01_2 = {b0 4c 6a 08 59 } 		$a_01_3 = {b0 4c 6a 10 59 } 		$a_01_4 = {ab b0 4c 6a 08 } 		$a_01_5 = {8b d0 c1 c2 10 } 		$a_01_6 = {8b d0 c1 e2 10 } 		$a_01_7 = {8b f0 c1 e6 10 } 		$a_01_8 = {c1 c6 10 64 ff 31 } 		$a_00_9 = {6d 6d 63 6e 64 6d 67 72 2e 64 6c 6c } 		$a_00_10 = {6d 73 66 74 65 64 69 74 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=11
 
}