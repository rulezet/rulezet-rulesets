rule VirTool_WinNT_Drvheed_A{
	meta:
		description = "VirTool:WinNT/Drvheed.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 06 68 89 7e 01 c6 46 05 c3 } 		$a_01_1 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 } 		$a_01_2 = {81 20 ff ff ff fd 0f b7 56 06 83 c0 28 41 3b ca 72 ee } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}