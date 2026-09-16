rule HackTool_Win32_Mimikatz_NPTT{
	meta:
		description = "HackTool:Win32/Mimikatz.NPTT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_80_0 = {6b 65 72 62 65 72 6f 73 3a 3a 70 74 74 20 90 02 40 40 } 	condition:
		((#a_80_0  & 1)*1) >=1
 
}