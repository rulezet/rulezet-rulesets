rule HackTool_Win32_KMSActivator_G_MSR{
	meta:
		description = "HackTool:Win32/KMSActivator.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 4d 53 2d 52 40 31 6e 48 6f 6f 6b 2e 70 64 62 } 		$a_01_1 = {4b 4d 53 2d 52 40 31 6e 48 6f 6f 6b 2e 64 6c 6c } 		$a_01_2 = {67 65 74 5f 4b 4d 53 5f 52 5f 31 6e 48 6f 6f 6b 33 32 45 58 45 } 		$a_01_3 = {41 63 74 69 76 61 74 6f 72 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}