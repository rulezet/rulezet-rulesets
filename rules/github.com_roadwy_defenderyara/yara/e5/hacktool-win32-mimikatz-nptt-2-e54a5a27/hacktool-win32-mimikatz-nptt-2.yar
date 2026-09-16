rule HackTool_Win32_Mimikatz_NPTT_2{
	meta:
		description = "HackTool:Win32/Mimikatz.NPTT,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_80_0 = {73 65 6b 75 72 6c 73 61 3a 3a 74 69 63 6b 65 74 73 20 2f 65 78 70 6f 72 74 } 	condition:
		((#a_80_0  & 1)*1) >=1
 
}