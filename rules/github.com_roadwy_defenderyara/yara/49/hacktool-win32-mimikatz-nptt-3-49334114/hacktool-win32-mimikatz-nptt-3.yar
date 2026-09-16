rule HackTool_Win32_Mimikatz_NPTT_3{
	meta:
		description = "HackTool:Win32/Mimikatz.NPTT,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_80_0 = {6c 73 61 64 75 6d 70 3a 3a 64 63 73 79 6e 63 } 		$a_80_1 = {2f 75 73 65 72 } 		$a_80_2 = {2f 64 6f 6d 61 69 6e } 	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=11
 
}