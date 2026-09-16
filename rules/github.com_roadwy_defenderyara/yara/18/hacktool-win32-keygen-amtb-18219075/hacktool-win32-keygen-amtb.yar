rule HackTool_Win32_Keygen_AMTB{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 67 65 6e 6e 65 64 20 62 79 } 		$a_01_1 = {46 46 46 4b 45 59 47 45 4e } 		$a_01_2 = {46 69 47 48 54 69 4e 47 20 46 4f 52 20 46 55 4e 20 50 52 45 53 45 4e 54 53 } 		$a_01_3 = {53 65 56 65 4e 20 2f 20 46 46 46 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}