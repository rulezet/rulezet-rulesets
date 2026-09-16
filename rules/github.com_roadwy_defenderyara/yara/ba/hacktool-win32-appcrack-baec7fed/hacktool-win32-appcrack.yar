rule HackTool_Win32_Appcrack{
	meta:
		description = "HackTool:Win32/Appcrack,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 61 63 6b 49 74 5f 43 6c 69 63 6b } 		$a_01_1 = {77 69 6e 72 74 5f 63 72 61 63 6b 69 6e 67 5c } 		$a_01_2 = {42 72 75 74 65 44 69 67 5f 43 6c 69 63 6b } 		$a_01_3 = {44 00 69 00 67 00 20 00 66 00 6f 00 72 00 20 00 2e 00 61 00 70 00 70 00 78 00 20 00 55 00 52 00 4c 00 73 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}