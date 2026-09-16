rule HackTool_Win32_Mimikatz_NPTT_4{
	meta:
		description = "HackTool:Win32/Mimikatz.NPTT,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_80_0 = {6b 65 72 62 65 72 6f 73 3a 3a 67 6f 6c 64 65 6e } 		$a_80_1 = {2f 75 73 65 72 } 		$a_80_2 = {2f 64 6f 6d 61 69 6e } 	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=11
 
}