rule HackTool_Win32_AutoKMS_D_2{
	meta:
		description = "HackTool:Win32/AutoKMS.D,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 38 35 2e 31 32 35 2e 32 33 30 2e 32 31 30 2f 4b 4d 53 70 69 63 6f 2d 73 65 74 75 70 2e 65 78 65 } 		$a_01_1 = {53 65 74 75 70 3d 4b 4d 53 70 69 63 6f 2d 73 65 74 75 70 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}